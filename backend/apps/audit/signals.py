from __future__ import annotations

from django.apps import apps
from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .context import get_audit_context
from .models import AuditEvent


def _get_user(user_id: int | None):
    if not user_id:
        return None
    User = get_user_model()
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None


def _should_audit(sender) -> bool:
    # Don't audit audit events to avoid recursion/noise.
    return sender is not AuditEvent


def _get_org_id(instance) -> int | None:
    """
    Best-effort org extraction for org-scoped models.
    """

    org_id = getattr(instance, "organization_id", None)
    return int(org_id) if org_id else None


@receiver(post_save)
def audit_save(sender, instance, created, **kwargs):
    if not _should_audit(sender):
        return
    if sender._meta.app_label not in {
        "core",
        "people",
        "assets",
        "docsapp",
        "secretsapp",
        "netapp",
        "flexassets",
        "checklists",
        "integrations",
        "workflows",
        "versionsapp",
        "backups",
    }:
        return

    ctx = get_audit_context()
    AuditEvent.objects.create(
        user=_get_user(ctx.user_id),
        ip=ctx.ip,
        organization_id=_get_org_id(instance),
        action=AuditEvent.ACTION_CREATE if created else AuditEvent.ACTION_UPDATE,
        model=f"{sender._meta.app_label}.{sender.__name__}",
        object_pk=str(getattr(instance, "pk", "")),
        summary=str(instance)[:500],
    )


@receiver(post_delete)
def audit_delete(sender, instance, **kwargs):
    if not _should_audit(sender):
        return
    if sender._meta.app_label not in {
        "core",
        "people",
        "assets",
        "docsapp",
        "secretsapp",
        "netapp",
        "flexassets",
        "checklists",
        "integrations",
        "workflows",
        "versionsapp",
        "backups",
    }:
        return

    ctx = get_audit_context()
    AuditEvent.objects.create(
        user=_get_user(ctx.user_id),
        ip=ctx.ip,
        organization_id=_get_org_id(instance),
        action=AuditEvent.ACTION_DELETE,
        model=f"{sender._meta.app_label}.{sender.__name__}",
        object_pk=str(getattr(instance, "pk", "")),
        summary=str(instance)[:500],
    )
