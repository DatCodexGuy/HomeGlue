from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.core.models import OrganizationMembership
from apps.assets.models import ConfigurationItem
from apps.assets.models import Asset
from apps.checklists.models import ChecklistRun
from apps.netapp.models import Domain, SSLCertificate
from apps.secretsapp.models import PasswordEntry

from .models import Notification, WorkflowRule


def _days_param(rule: WorkflowRule, default_days: int) -> int:
    try:
        raw = (rule.params or {}).get("days")
        if raw is None:
            return int(default_days)
        n = int(raw)
        return max(1, min(3650, n))
    except Exception:
        return int(default_days)


def _int_param(rule: WorkflowRule, key: str, default: int, *, min_value: int, max_value: int) -> int:
    try:
        raw = (rule.params or {}).get(key)
        if raw is None:
            return int(default)
        n = int(raw)
        return max(int(min_value), min(int(max_value), n))
    except Exception:
        return int(default)


def _audience_user_ids(rule: WorkflowRule) -> list[int]:
    qs = OrganizationMembership.objects.filter(organization=rule.organization).select_related("user")
    if rule.audience == WorkflowRule.AUDIENCE_ADMINS:
        qs = qs.filter(role__in=[OrganizationMembership.ROLE_OWNER, OrganizationMembership.ROLE_ADMIN])
    return list(qs.values_list("user_id", flat=True))


def _create_notification_for_users(
    *,
    rule: WorkflowRule,
    user_ids: list[int],
    dedupe_key: str,
    level: str,
    title: str,
    body: str,
    ct: ContentType | None,
    object_id: str | None,
) -> int:
    created = 0
    for uid in user_ids:
        _, was_created = Notification.objects.get_or_create(
            organization=rule.organization,
            user_id=int(uid),
            dedupe_key=dedupe_key[:255],
            defaults={
                "rule": rule,
                "level": level,
                "title": title[:200],
                "body": body,
                "content_type": ct,
                "object_id": object_id,
            },
        )
        if was_created:
            created += 1
    return created


@dataclass(frozen=True)
class RuleRunResult:
    ok: bool
    notifications_created: int = 0
    error: str = ""


@transaction.atomic
def run_rule(rule: WorkflowRule) -> RuleRunResult:
    """
    Evaluate a single rule and create notifications (deduped per user).
    """

    if not rule.enabled:
        return RuleRunResult(ok=False, error="disabled")

    today = date.today()
    users = _audience_user_ids(rule)
    if not users:
        return RuleRunResult(ok=True, notifications_created=0)

    created = 0

    if rule.kind == WorkflowRule.KIND_DOMAIN_EXPIRY:
        days = _days_param(rule, 30)
        cutoff = today + timedelta(days=days)
        qs = Domain.objects.filter(
            organization=rule.organization,
            archived_at__isnull=True,
            expires_on__isnull=False,
            expires_on__lte=cutoff,
        ).order_by("expires_on")[:500]
        ct = ContentType.objects.get_for_model(Domain)
        for d in qs:
            dedupe = f"rule:{rule.id}:domain:{d.id}:expires:{d.expires_on.isoformat()}"
            title = f"Domain expiring: {d.name}"
            body = f"Expires on {d.expires_on.isoformat()} (<= {days} days)."
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_WARN if (d.expires_on and d.expires_on > today) else Notification.LEVEL_DANGER,
                title=title,
                body=body,
                ct=ct,
                object_id=str(d.id),
            )

    elif rule.kind == WorkflowRule.KIND_SSL_EXPIRY:
        days = _days_param(rule, 30)
        cutoff = today + timedelta(days=days)
        qs = SSLCertificate.objects.filter(
            organization=rule.organization,
            archived_at__isnull=True,
            not_after__isnull=False,
            not_after__lte=cutoff,
        ).order_by("not_after")[:500]
        ct = ContentType.objects.get_for_model(SSLCertificate)
        for c in qs:
            if not c.not_after:
                continue
            label = c.common_name or f"Cert {c.id}"
            dedupe = f"rule:{rule.id}:ssl:{c.id}:expires:{c.not_after.isoformat()}"
            title = f"SSL expiring: {label}"
            body = f"Expires on {c.not_after.isoformat()} (<= {days} days)."
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_WARN if (c.not_after and c.not_after > today) else Notification.LEVEL_DANGER,
                title=title,
                body=body,
                ct=ct,
                object_id=str(c.id),
            )

    elif rule.kind == WorkflowRule.KIND_CHECKLIST_RUN_OVERDUE:
        grace = _int_param(rule, "grace_days", 0, min_value=0, max_value=3650)
        cutoff = today - timedelta(days=int(grace))
        filt = {
            "organization": rule.organization,
            "archived_at__isnull": True,
            "status": ChecklistRun.STATUS_OPEN,
            "due_on__isnull": False,
        }
        if int(grace) == 0:
            filt["due_on__lt"] = cutoff
        else:
            filt["due_on__lte"] = cutoff
        qs = ChecklistRun.objects.filter(**filt).order_by("due_on")[:500]
        ct = ContentType.objects.get_for_model(ChecklistRun)
        for r in qs:
            if not r.due_on:
                continue
            overdue_days = max(0, (today - r.due_on).days)
            dedupe = f"rule:{rule.id}:checklistrun:{r.id}:due:{r.due_on.isoformat()}:grace:{grace}"
            title = f"Checklist run overdue: {r.name}"
            body = f"Due on {r.due_on.isoformat()} ({overdue_days} day(s) overdue)."
            level = Notification.LEVEL_WARN if overdue_days <= 7 else Notification.LEVEL_DANGER
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=level,
                title=title,
                body=body,
                ct=ct,
                object_id=str(r.id),
            )

    elif rule.kind == WorkflowRule.KIND_CONFIG_MISSING_PRIMARY_IP:
        qs = ConfigurationItem.objects.filter(
            organization=rule.organization,
            archived_at__isnull=True,
        ).filter(Q(primary_ip__isnull=True) | Q(primary_ip="")).order_by("name")[:500]
        ct = ContentType.objects.get_for_model(ConfigurationItem)
        for ci in qs:
            upd = None
            try:
                upd = (ci.updated_at.date().isoformat() if getattr(ci, "updated_at", None) else None) or "na"
            except Exception:
                upd = "na"
            dedupe = f"rule:{rule.id}:config:{ci.id}:missing_primary_ip:updated:{upd}"
            title = f"Missing primary IP: {ci.name}"
            body = "Configuration item has no primary IP."
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_WARN,
                title=title,
                body=body,
                ct=ct,
                object_id=str(ci.id),
            )

    elif rule.kind == WorkflowRule.KIND_ASSET_MISSING_LOCATION:
        qs = Asset.objects.filter(organization=rule.organization, archived_at__isnull=True, location__isnull=True).order_by("name")[:500]
        ct = ContentType.objects.get_for_model(Asset)
        for a in qs:
            upd = None
            try:
                upd = (a.created_at.date().isoformat() if getattr(a, "created_at", None) else None) or "na"
            except Exception:
                upd = "na"
            dedupe = f"rule:{rule.id}:asset:{a.id}:missing_location:created:{upd}"
            title = f"Missing location: {a.name}"
            body = "Asset has no location set."
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_WARN,
                title=title,
                body=body,
                ct=ct,
                object_id=str(a.id),
            )

    elif rule.kind == WorkflowRule.KIND_PASSWORD_MISSING_URL:
        qs = PasswordEntry.objects.filter(organization=rule.organization, archived_at__isnull=True).filter(Q(url__isnull=True) | Q(url="")).order_by("name")[:500]
        ct = ContentType.objects.get_for_model(PasswordEntry)
        for p in qs:
            upd = None
            try:
                upd = (p.created_at.date().isoformat() if getattr(p, "created_at", None) else None) or "na"
            except Exception:
                upd = "na"
            dedupe = f"rule:{rule.id}:password:{p.id}:missing_url:created:{upd}"
            title = f"Missing URL: {p.name}"
            body = "Password entry has no URL set."
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_WARN,
                title=title,
                body=body,
                ct=ct,
                object_id=str(p.id),
            )

    elif rule.kind == WorkflowRule.KIND_PASSWORD_ROTATION_DUE:
        days = _days_param(rule, 7)
        cutoff = today + timedelta(days=days)
        qs = (
            PasswordEntry.objects.filter(organization=rule.organization, archived_at__isnull=True, rotation_interval_days__gt=0)
            .order_by("id")[:2000]
        )
        ct = ContentType.objects.get_for_model(PasswordEntry)
        for p in qs:
            due = None
            try:
                due = p.rotation_due_on()
            except Exception:
                due = None
            if not due:
                continue
            if due > cutoff:
                continue
            dedupe = f"rule:{rule.id}:password:{p.id}:rotation_due:{due.isoformat()}"
            title = f"Password rotation due: {p.name}"
            body = f"Rotation due on {due.isoformat()} (<= {days} days)."
            level = Notification.LEVEL_WARN if due > today else Notification.LEVEL_DANGER
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=level,
                title=title,
                body=body,
                ct=ct,
                object_id=str(p.id),
            )

    else:
        return RuleRunResult(ok=False, error=f"unknown kind: {rule.kind}")

    rule.last_run_at = timezone.now()
    rule.last_run_ok = True
    rule.last_run_error = ""
    rule.save(update_fields=["last_run_at", "last_run_ok", "last_run_error", "updated_at"])
    return RuleRunResult(ok=True, notifications_created=created)


def run_due_rules(*, org_id: int | None = None) -> int:
    """
    Run due rules once. Returns number of notifications created.
    """

    qs = WorkflowRule.objects.filter(enabled=True).order_by("id")
    if org_id:
        qs = qs.filter(organization_id=int(org_id))

    now = timezone.now()
    due: list[WorkflowRule] = []
    for r in qs:
        interval = int(r.run_interval_minutes or 0)
        if interval <= 0:
            continue
        if not r.last_run_at:
            due.append(r)
            continue
        if r.last_run_at <= now - timezone.timedelta(minutes=interval):
            due.append(r)

    created = 0
    for r in due:
        try:
            res = run_rule(r)
            created += int(res.notifications_created or 0)
        except Exception as e:
            r.last_run_at = timezone.now()
            r.last_run_ok = False
            r.last_run_error = str(e)
            r.save(update_fields=["last_run_at", "last_run_ok", "last_run_error", "updated_at"])
    return created
