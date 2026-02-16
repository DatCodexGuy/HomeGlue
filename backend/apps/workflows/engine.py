from __future__ import annotations

from time import monotonic
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
from apps.backups.models import BackupSnapshot
from apps.integrations.models import ProxmoxConnection

from .models import Notification, WorkflowRule, WorkflowRuleRun


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


def _admin_user_ids_for_org(org) -> set[int]:
    qs = OrganizationMembership.objects.filter(
        organization=org,
        role__in=[OrganizationMembership.ROLE_OWNER, OrganizationMembership.ROLE_ADMIN],
    )
    return {int(x) for x in qs.values_list("user_id", flat=True)}


def _visible_users_for_password(
    *,
    p: PasswordEntry,
    audience_user_ids: list[int],
    admin_user_ids: set[int],
) -> list[int]:
    """
    Limit password-related notifications to users who can actually view the PasswordEntry.
    This prevents workflow notifications from leaking password existence/metadata.
    """

    base = {int(x) for x in (audience_user_ids or [])}
    if not base:
        return []

    vis = (p.visibility or PasswordEntry.VIS_ADMINS).strip().lower()
    creator_id = int(p.created_by_id) if getattr(p, "created_by_id", None) else None

    allowed: set[int]
    if vis == PasswordEntry.VIS_ORG:
        allowed = set(base)
    elif vis == PasswordEntry.VIS_ADMINS:
        allowed = set(admin_user_ids)
        if creator_id:
            allowed.add(int(creator_id))
    elif vis == PasswordEntry.VIS_PRIVATE:
        allowed = set(admin_user_ids)
        if creator_id:
            allowed.add(int(creator_id))
    elif vis == PasswordEntry.VIS_SHARED:
        allowed = set(admin_user_ids)
        if creator_id:
            allowed.add(int(creator_id))
        try:
            allowed |= {int(x) for x in p.allowed_users.values_list("id", flat=True)}
        except Exception:
            pass
    else:
        allowed = set(admin_user_ids)
        if creator_id:
            allowed.add(int(creator_id))

    return sorted(set(base) & allowed)


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
def _run_rule_eval(rule: WorkflowRule) -> int:
    """
    Evaluate a single enabled rule and create notifications (deduped per user).
    Returns number of notifications created.
    """

    today = date.today()
    users = _audience_user_ids(rule)
    if not users:
        return 0

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
        qs = (
            PasswordEntry.objects.filter(organization=rule.organization, archived_at__isnull=True)
            .filter(Q(url__isnull=True) | Q(url=""))
            .select_related("created_by")
            .prefetch_related("allowed_users")
            .order_by("name")[:500]
        )
        ct = ContentType.objects.get_for_model(PasswordEntry)
        admin_ids = _admin_user_ids_for_org(rule.organization)
        for p in qs:
            upd = None
            try:
                upd = (p.created_at.date().isoformat() if getattr(p, "created_at", None) else None) or "na"
            except Exception:
                upd = "na"
            dedupe = f"rule:{rule.id}:password:{p.id}:missing_url:created:{upd}"
            title = f"Missing URL: {p.name}"
            body = "Password entry has no URL set."
            target_users = _visible_users_for_password(p=p, audience_user_ids=users, admin_user_ids=admin_ids)
            if not target_users:
                continue
            created += _create_notification_for_users(
                rule=rule,
                user_ids=target_users,
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
            .select_related("created_by")
            .prefetch_related("allowed_users")
            .order_by("id")[:2000]
        )
        ct = ContentType.objects.get_for_model(PasswordEntry)
        admin_ids = _admin_user_ids_for_org(rule.organization)
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
            target_users = _visible_users_for_password(p=p, audience_user_ids=users, admin_user_ids=admin_ids)
            if not target_users:
                continue
            created += _create_notification_for_users(
                rule=rule,
                user_ids=target_users,
                dedupe_key=dedupe,
                level=level,
                title=title,
                body=body,
                ct=ct,
                object_id=str(p.id),
            )

    elif rule.kind == WorkflowRule.KIND_BACKUP_FAILED_RECENT:
        days = _days_param(rule, 7)
        since = timezone.now() - timezone.timedelta(days=int(days))
        qs = BackupSnapshot.objects.filter(
            organization=rule.organization,
            status=BackupSnapshot.STATUS_FAILED,
            created_at__gte=since,
        ).order_by("-created_at")[:200]
        ct = ContentType.objects.get_for_model(BackupSnapshot)
        for b in qs:
            when = b.created_at.date().isoformat() if b.created_at else "na"
            dedupe = f"rule:{rule.id}:backup:{b.id}:failed:{when}"
            title = "Backup failed"
            body = f"Snapshot {b.id} failed on {when}."
            if b.error:
                body = body + f"\n\nError: {str(b.error)[:800]}"
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_DANGER,
                title=title,
                body=body,
                ct=ct,
                object_id=str(b.id),
            )

    elif rule.kind == WorkflowRule.KIND_PROXMOX_SYNC_STALE:
        stale_minutes = _int_param(rule, "stale_minutes", 120, min_value=5, max_value=60 * 24 * 30)
        cutoff = timezone.now() - timezone.timedelta(minutes=int(stale_minutes))
        qs = (
            ProxmoxConnection.objects.filter(organization=rule.organization, enabled=True, sync_interval_minutes__gt=0)
            .order_by("name", "id")[:50]
        )
        ct = ContentType.objects.get_for_model(ProxmoxConnection)
        for c in qs:
            last = getattr(c, "last_sync_at", None)
            stale = (last is None) or (last <= cutoff)
            if not stale:
                continue
            label = c.name or "Proxmox"
            last_s = last.isoformat() if last else "never"
            ok = bool(getattr(c, "last_sync_ok", False))
            err = (getattr(c, "last_sync_error", "") or "").strip()
            # Dedupe by the last sync timestamp; a new sync attempt updates last_sync_at.
            dedupe = f"rule:{rule.id}:proxmox:{c.id}:last:{last_s}:ok:{int(ok)}"
            title = f"Proxmox sync stale: {label}"
            body = f"Last sync: {last_s} (stale > {int(stale_minutes)} minutes)."
            if err:
                body = body + f"\n\nLast error: {err[:800]}"
            created += _create_notification_for_users(
                rule=rule,
                user_ids=users,
                dedupe_key=dedupe,
                level=Notification.LEVEL_WARN if last else Notification.LEVEL_DANGER,
                title=title,
                body=body,
                ct=ct,
                object_id=str(c.id),
            )

    else:
        raise ValueError(f"unknown kind: {rule.kind}")

    return int(created)


def run_rule(rule: WorkflowRule, *, triggered_by: str = WorkflowRuleRun.TRIGGER_WORKER, triggered_by_user=None) -> RuleRunResult:
    """
    Evaluate a single rule and record an execution record (WorkflowRuleRun).

    This is best-effort: rule runs should never crash the worker loop.
    """

    started_at = timezone.now()
    t0 = monotonic()
    ok = False
    created = 0
    err = ""

    try:
        if not rule.enabled:
            err = "disabled"
            return RuleRunResult(ok=False, error=err)
        created = _run_rule_eval(rule)
        ok = True
        return RuleRunResult(ok=True, notifications_created=int(created or 0))
    except Exception as e:
        ok = False
        err = str(e)[:2000]
        return RuleRunResult(ok=False, notifications_created=int(created or 0), error=err)
    finally:
        finished_at = timezone.now()
        dur_ms = int(max(0.0, (monotonic() - t0) * 1000.0))

        try:
            WorkflowRuleRun.objects.create(
                organization=rule.organization,
                rule=rule,
                triggered_by=str(triggered_by or WorkflowRuleRun.TRIGGER_WORKER)[:16],
                triggered_by_user=triggered_by_user if (triggered_by_user and getattr(triggered_by_user, "is_authenticated", False)) else None,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=dur_ms,
                ok=bool(ok),
                notifications_created=int(created or 0),
                error=(err or "")[:4000],
            )
        except Exception:
            pass

        # Update last-run status (best-effort). This is separate from the run record.
        try:
            rule.last_run_at = finished_at
            rule.last_run_ok = bool(ok)
            rule.last_run_error = "" if ok else (err or "")[:4000]
            rule.save(update_fields=["last_run_at", "last_run_ok", "last_run_error", "updated_at"])
        except Exception:
            pass


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
        res = run_rule(r, triggered_by=WorkflowRuleRun.TRIGGER_WORKER)
        created += int(res.notifications_created or 0)
    return created
