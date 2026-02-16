from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.core.models import Organization
from apps.workflows.models import WorkflowRule


class Command(BaseCommand):
    help = "Seed default workflow rules. Safe to re-run."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Seed only one organization.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        qs = Organization.objects.all().order_by("id")
        if org_id:
            qs = qs.filter(id=int(org_id))

        for org in qs:
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_DOMAIN_EXPIRY,
                name="Domain expiry (30d)",
                defaults={"params": {"days": 30}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 60},
            )
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_SSL_EXPIRY,
                name="SSL expiry (30d)",
                defaults={"params": {"days": 30}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 60},
            )
            # Non-expiry "hygiene" rules are seeded disabled to avoid surprising new installs.
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_CHECKLIST_RUN_OVERDUE,
                name="Checklist runs overdue",
                defaults={"params": {"grace_days": 0}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 60, "enabled": False},
            )
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_CONFIG_MISSING_PRIMARY_IP,
                name="Config items missing primary IP",
                defaults={"params": {}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
            )
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_ASSET_MISSING_LOCATION,
                name="Assets missing location",
                defaults={"params": {}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
            )
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_PASSWORD_MISSING_URL,
                name="Passwords missing URL",
                defaults={"params": {}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
            )
            WorkflowRule.objects.get_or_create(
                organization=org,
                kind=WorkflowRule.KIND_PASSWORD_ROTATION_DUE,
                name="Password rotations due (7d)",
                defaults={"params": {"days": 7}, "audience": WorkflowRule.AUDIENCE_ADMINS, "run_interval_minutes": 240, "enabled": False},
            )
            self.stdout.write(self.style.SUCCESS(f"Seeded rules for org={org.id} {org.name}"))
