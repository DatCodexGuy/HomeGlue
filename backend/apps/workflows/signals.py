from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.core.models import Organization
from apps.workflows.models import WorkflowRule


@receiver(post_save, sender=Organization)
def _seed_default_workflow_rules(sender, instance: Organization, created: bool, **kwargs):
    """
    Ensure baseline workflow rules exist for every org.
    Safe to run multiple times.
    """

    if not created:
        return

    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_DOMAIN_EXPIRY,
        name="Domain expiry (30d)",
        defaults={"params": {"days": 30}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 60},
    )
    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_SSL_EXPIRY,
        name="SSL expiry (30d)",
        defaults={"params": {"days": 30}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 60},
    )

    # Seed additional rule types disabled (avoid surprising new installs).
    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_CHECKLIST_RUN_OVERDUE,
        name="Checklist runs overdue",
        defaults={"params": {"grace_days": 0}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 60, "enabled": False},
    )
    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_CONFIG_MISSING_PRIMARY_IP,
        name="Config items missing primary IP",
        defaults={"params": {}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
    )
    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_ASSET_MISSING_LOCATION,
        name="Assets missing location",
        defaults={"params": {}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
    )
    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_PASSWORD_MISSING_URL,
        name="Passwords missing URL",
        defaults={"params": {}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
    )
    WorkflowRule.objects.get_or_create(
        organization=instance,
        kind=WorkflowRule.KIND_PASSWORD_ROTATION_DUE,
        name="Password rotations due (7d)",
        defaults={"params": {"days": 7}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
    )
