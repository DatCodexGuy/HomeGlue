from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.backups.models import BackupPolicy, BackupSnapshot
from apps.core.models import Organization


class Command(BaseCommand):
    help = "Schedule org backup snapshots based on BackupPolicy (creates pending snapshots + enforces retention)."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")
        parser.add_argument("--force", action="store_true", help="Schedule a snapshot even if not due (still avoids duplicate pending/running).")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        force = bool(opts.get("force"))
        now = timezone.now()

        org_qs = Organization.objects.all().order_by("id")
        if org_id:
            org_qs = org_qs.filter(id=int(org_id))

        for org in list(org_qs):
            policy, _ = BackupPolicy.objects.get_or_create(organization=org)
            if not policy.enabled:
                continue

            # Avoid piling up work: one pending/running snapshot per org at a time.
            if BackupSnapshot.objects.filter(
                organization=org, status__in=[BackupSnapshot.STATUS_PENDING, BackupSnapshot.STATUS_RUNNING]
            ).exists():
                continue

            due = force or (policy.next_run_at is None) or (policy.next_run_at <= now)
            if not due:
                continue

            BackupSnapshot.objects.create(organization=org, created_by=None, status=BackupSnapshot.STATUS_PENDING)

            interval_h = int(policy.interval_hours or 24)
            if interval_h <= 0:
                interval_h = 24
            policy.last_scheduled_at = now
            policy.next_run_at = now + timedelta(hours=interval_h)
            policy.save(update_fields=["last_scheduled_at", "next_run_at", "updated_at"])

            # Retention: keep only the newest N successful snapshots.
            keep = int(policy.retention_count or 0)
            if keep < 0:
                keep = 0
            if keep:
                old_ids = list(
                    BackupSnapshot.objects.filter(organization=org, status=BackupSnapshot.STATUS_SUCCESS)
                    .order_by("-created_at")
                    .values_list("id", flat=True)[keep:]
                )
            else:
                old_ids = list(
                    BackupSnapshot.objects.filter(organization=org, status=BackupSnapshot.STATUS_SUCCESS)
                    .order_by("-created_at")
                    .values_list("id", flat=True)
                )
            if old_ids:
                for b in BackupSnapshot.objects.filter(id__in=old_ids):
                    try:
                        b.delete()
                    except Exception:
                        continue

