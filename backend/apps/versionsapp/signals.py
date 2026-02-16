from __future__ import annotations

import threading

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_save
from django.dispatch import receiver

from apps.audit.context import get_audit_context

from .models import ObjectVersion
from .utils import serialize_instance

_local = threading.local()


def _get_user(user_id: int | None):
    if not user_id:
        return None
    User = get_user_model()
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None


def _org_id_for_instance(instance) -> int | None:
    org_id = getattr(instance, "organization_id", None)
    if org_id:
        return int(org_id)
    # Some objects (e.g. integrations) scope via connection -> organization.
    conn = getattr(instance, "connection", None)
    if conn is not None and getattr(conn, "organization_id", None):
        return int(conn.organization_id)
    return None


def _should_version(sender) -> bool:
    if sender is ObjectVersion:
        return False
    return sender._meta.app_label in {"assets", "docsapp", "secretsapp", "netapp", "flexassets"}


def _old_map() -> dict:
    d = getattr(_local, "old", None)
    if d is None:
        d = {}
        _local.old = d
    return d


@receiver(pre_save)
def version_pre_save(sender, instance, **kwargs):
    if not _should_version(sender):
        return
    pk = getattr(instance, "pk", None)
    if not pk:
        return
    try:
        old = sender.objects.get(pk=pk)
    except Exception:
        return
    _old_map()[(sender._meta.label_lower, str(pk))] = serialize_instance(old)


@receiver(post_save)
def version_post_save(sender, instance, created, **kwargs):
    if not _should_version(sender):
        return
    org_id = _org_id_for_instance(instance)
    if not org_id:
        return

    ct = ContentType.objects.get_for_model(sender)
    snap = serialize_instance(instance)

    ctx = get_audit_context()
    user = _get_user(ctx.user_id)

    if created:
        ObjectVersion.objects.create(
            organization_id=org_id,
            content_type=ct,
            object_id=str(instance.pk),
            action=ObjectVersion.ACTION_CREATE,
            created_by=user,
            summary=str(instance)[:255],
            snapshot=snap,
        )
        return

    key = (sender._meta.label_lower, str(instance.pk))
    old = _old_map().pop(key, None)
    if old == snap:
        return

    ObjectVersion.objects.create(
        organization_id=org_id,
        content_type=ct,
        object_id=str(instance.pk),
        action=ObjectVersion.ACTION_UPDATE,
        created_by=user,
        summary=str(instance)[:255],
        snapshot=snap,
    )


@receiver(post_delete)
def version_post_delete(sender, instance, **kwargs):
    if not _should_version(sender):
        return
    org_id = _org_id_for_instance(instance)
    if not org_id:
        return
    ct = ContentType.objects.get_for_model(sender)
    ctx = get_audit_context()
    user = _get_user(ctx.user_id)
    try:
        snap = serialize_instance(instance)
    except Exception:
        snap = {}

    ObjectVersion.objects.create(
        organization_id=org_id,
        content_type=ct,
        object_id=str(getattr(instance, "pk", "")),
        action=ObjectVersion.ACTION_DELETE,
        created_by=user,
        summary=str(instance)[:255],
        snapshot=snap,
    )


def _register_m2m(model_label: str, field_name: str):
    try:
        model = apps.get_model(model_label)
        field = model._meta.get_field(field_name)
        through = field.remote_field.through
    except Exception:
        return

    @receiver(m2m_changed, sender=through, weak=False)
    def _on_m2m(sender, instance, action, **kwargs):  # type: ignore[no-redef]
        if action not in {"post_add", "post_remove", "post_clear"}:
            return
        if not _should_version(instance.__class__):
            return
        org_id = _org_id_for_instance(instance)
        if not org_id:
            return
        ct = ContentType.objects.get_for_model(instance.__class__)
        ctx = get_audit_context()
        user = _get_user(ctx.user_id)
        snap = serialize_instance(instance)
        ObjectVersion.objects.create(
            organization_id=org_id,
            content_type=ct,
            object_id=str(instance.pk),
            action=ObjectVersion.ACTION_UPDATE,
            created_by=user,
            summary=str(instance)[:255],
            snapshot=snap,
        )


# Track tag/domain linking changes, since they occur after save().
_register_m2m("assets.Asset", "tags")
_register_m2m("assets.ConfigurationItem", "tags")
_register_m2m("docsapp.Document", "tags")
_register_m2m("docsapp.DocumentTemplate", "tags")
_register_m2m("secretsapp.PasswordEntry", "tags")
_register_m2m("netapp.Domain", "tags")
_register_m2m("netapp.SSLCertificate", "tags")
_register_m2m("netapp.SSLCertificate", "domains")
_register_m2m("flexassets.FlexibleAsset", "tags")

