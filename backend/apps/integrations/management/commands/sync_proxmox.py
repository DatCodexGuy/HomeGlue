from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from apps.integrations.models import ProxmoxConnection
from apps.integrations.proxmox import sync_proxmox_connection


class Command(BaseCommand):
    help = "Sync Proxmox inventory for a connection (or all enabled connections)."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")
        parser.add_argument("--connection-id", type=int, default=None, help="Sync a specific ProxmoxConnection id.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        conn_id = opts.get("connection_id")

        qs = ProxmoxConnection.objects.all().order_by("id")
        if org_id:
            qs = qs.filter(organization_id=int(org_id))
        if conn_id:
            qs = qs.filter(id=int(conn_id))
        else:
            qs = qs.filter(enabled=True)

        conns = list(qs)
        if not conns:
            raise CommandError("No matching Proxmox connections found.")

        any_failed = False
        for c in conns:
            self.stdout.write(f"Syncing {c.id} {c.organization_id} {c.name} ...")
            res = sync_proxmox_connection(c)
            if not res.ok:
                any_failed = True
                self.stdout.write(self.style.ERROR(f"  FAILED: {res.error}"))
            else:
                self.stdout.write(self.style.SUCCESS(f"  OK: nodes={res.nodes} guests={res.guests} nets={res.networks}"))

        if any_failed:
            raise CommandError("One or more Proxmox syncs failed. Check the connection details and try again.")
