from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import urllib.request

from django.conf import settings
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.db.models import Q
from django.utils import timezone

from apps.core.system_settings import get_base_url
from apps.core.system_settings import get_email_settings
from apps.workflows.models import Notification, NotificationDeliveryAttempt, WebhookEndpoint


def _email_enabled() -> bool:
    cfg = get_email_settings()
    return bool(cfg.get("enabled"))


def _build_email_body(n: Notification) -> str:
    lines = []
    lines.append(f"Organization: {n.organization.name}")
    lines.append(f"Level: {n.level}")
    lines.append("")
    lines.append(n.title)
    if n.body:
        lines.append("")
        lines.append(n.body)
    lines.append("")
    lines.append("View in HomeGlue:")
    # Keep it simple: point users to the notifications list.
    base = (get_base_url() or "").rstrip("/")
    path = "/app/notifications/"
    if base:
        lines.append(f"{base}{path}")
    else:
        lines.append(path)
    return "\n".join(lines).strip() + "\n"


def _send_email_notification(n: Notification) -> tuple[bool, str]:
    user = n.user
    to = (getattr(user, "email", "") or "").strip()
    if not to:
        return (False, "user has no email")

    subject = f"[HomeGlue] {n.title}"
    body = _build_email_body(n)
    cfg = get_email_settings()
    from_email = (cfg.get("from_email") or "").strip() or getattr(settings, "DEFAULT_FROM_EMAIL", None) or "homeglue@localhost"
    try:
        if (cfg.get("source") == "db") and (str(cfg.get("backend") or "") in {"smtp", "smtp+tls", "smtp+ssl", "console"}):
            backend = str(cfg.get("backend") or "console").strip().lower()
            if backend == "console":
                from django.core.mail.backends.console import EmailBackend as ConsoleBackend

                conn = ConsoleBackend(fail_silently=False)
            else:
                from django.core.mail.backends.smtp import EmailBackend as SmtpBackend

                use_tls = bool(cfg.get("smtp_use_tls")) and backend in {"smtp", "smtp+tls"}
                use_ssl = bool(cfg.get("smtp_use_ssl")) or backend == "smtp+ssl"
                conn = SmtpBackend(
                    host=str(cfg.get("smtp_host") or ""),
                    port=int(cfg.get("smtp_port") or 587),
                    username=str(cfg.get("smtp_user") or ""),
                    password=str(cfg.get("smtp_password") or ""),
                    use_tls=use_tls,
                    use_ssl=use_ssl,
                    timeout=int(getattr(settings, "HOMEGLUE_SMTP_TIMEOUT_SECONDS", 10) or 10),
                    fail_silently=False,
                )
            msg = EmailMessage(subject=subject, body=body, from_email=from_email, to=[to], connection=conn)
            msg.send(fail_silently=False)
        else:
            # Env-backed behavior uses Django's configured email backend.
            send_mail(subject, body, from_email, [to], fail_silently=False)
        return (True, "")
    except Exception as e:
        return (False, str(e))


def _webhook_enabled_for_org(org_id: int) -> bool:
    # No global kill-switch; if org has enabled endpoints, we deliver.
    return WebhookEndpoint.objects.filter(organization_id=int(org_id), enabled=True).exists()


def _post_webhook(*, endpoint: WebhookEndpoint, payload: dict) -> tuple[bool, int | None, str]:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    secret = (endpoint.get_secret() or "").encode("utf-8")
    sig = hmac.new(secret, raw, hashlib.sha256).hexdigest() if secret else ""

    req = urllib.request.Request(endpoint.url, data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "HomeGlue/1.0")
    if sig:
        req.add_header("X-HomeGlue-Signature", f"sha256={sig}")
    req.add_header("X-HomeGlue-Org", str(endpoint.organization_id))

    timeout = int(getattr(settings, "HOMEGLUE_WEBHOOK_TIMEOUT_SECONDS", 8) or 8)
    ctx = None
    if not endpoint.verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = int(getattr(resp, "status", 200) or 200)
            if 200 <= code < 300:
                return (True, code, "")
            return (False, code, f"non-2xx: {code}")
    except Exception as e:
        return (False, None, str(e))


def deliver_workflow_notifications_once(*, org_id: int | None = None, limit: int = 200) -> dict[str, int]:
    """
    Deliver workflow notifications via email and webhook, best-effort.

    Idempotent per notification+channel(+endpoint) via NotificationDeliveryAttempt uniqueness.
    """

    limit = int(limit or 200)
    now = timezone.now()
    since = now - timezone.timedelta(days=30)

    qs = Notification.objects.select_related("organization", "user", "rule", "content_type").filter(created_at__gte=since)
    if org_id:
        qs = qs.filter(organization_id=int(org_id))
    # Only deliver unread by default to avoid sending late "noise" after users clear items.
    qs = qs.filter(read_at__isnull=True)

    delivered_email = 0
    delivered_webhook = 0

    # Email delivery
    if _email_enabled():
        for n in list(qs.order_by("-created_at")[:limit]):
            # Skip if already successfully delivered by email.
            if NotificationDeliveryAttempt.objects.filter(notification=n, kind=NotificationDeliveryAttempt.KIND_EMAIL, ok=True).exists():
                continue
            ok, err = _send_email_notification(n)
            NotificationDeliveryAttempt.objects.get_or_create(
                notification=n,
                kind=NotificationDeliveryAttempt.KIND_EMAIL,
                endpoint=None,
                defaults={"ok": bool(ok), "error": (err or "")[:2000]},
            )
            if ok:
                delivered_email += 1

    # Webhook delivery
    # We deliver to all enabled endpoints for the org, once per endpoint.
    org_ids = sorted(set(qs.values_list("organization_id", flat=True)))
    for oid in org_ids:
        if not _webhook_enabled_for_org(int(oid)):
            continue
        endpoints = list(WebhookEndpoint.objects.filter(organization_id=int(oid), enabled=True).order_by("id")[:50])
        if not endpoints:
            continue

        items = list(qs.filter(organization_id=int(oid)).order_by("-created_at")[:limit])
        for n in items:
            payload = {
                "id": n.id,
                "organization_id": n.organization_id,
                "user_id": n.user_id,
                "level": n.level,
                "title": n.title,
                "body": n.body,
                "rule_id": n.rule_id,
                "ref": f"{n.content_type.app_label}.{n.content_type.model}:{n.object_id}" if (n.content_type_id and n.object_id) else None,
                "read_at": n.read_at.isoformat() if n.read_at else None,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for ep in endpoints:
                if NotificationDeliveryAttempt.objects.filter(
                    notification=n, kind=NotificationDeliveryAttempt.KIND_WEBHOOK, endpoint=ep, ok=True
                ).exists():
                    continue
                ok, code, err = _post_webhook(endpoint=ep, payload=payload)
                NotificationDeliveryAttempt.objects.get_or_create(
                    notification=n,
                    kind=NotificationDeliveryAttempt.KIND_WEBHOOK,
                    endpoint=ep,
                    defaults={"ok": bool(ok), "status_code": code, "error": (err or "")[:2000]},
                )
                if ok:
                    delivered_webhook += 1

    return {"email": delivered_email, "webhook": delivered_webhook}
