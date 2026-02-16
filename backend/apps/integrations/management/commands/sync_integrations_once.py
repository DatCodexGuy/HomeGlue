from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.integrations.models import ProxmoxConnection
from apps.integrations.proxmox import sync_proxmox_connection


class Command(BaseCommand):
    help = "Sync due integrations once (currently: Proxmox). Intended to be run in a loop."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        qs = ProxmoxConnection.objects.filter(enabled=True).order_by("id")
        if org_id:
            qs = qs.filter(organization_id=int(org_id))

        now = timezone.now()
        due = []
        for c in qs:
            interval = int(c.sync_interval_minutes or 0)
            if interval <= 0:
                continue
            if not c.last_sync_at:
                due.append(c)
                continue
            if c.last_sync_at <= now - timedelta(minutes=interval):
                due.append(c)

        for c in due:
            self.stdout.write(f"Syncing Proxmox {c.id} org={c.organization_id} {c.name} ...")
            res = sync_proxmox_connection(c)
            if res.ok:
                self.stdout.write(self.style.SUCCESS(f"  OK nodes={res.nodes} guests={res.guests} nets={res.networks}"))
            else:
                self.stdout.write(self.style.ERROR(f"  FAILED {res.error}"))

