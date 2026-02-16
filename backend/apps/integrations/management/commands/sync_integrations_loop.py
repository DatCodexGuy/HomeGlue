from __future__ import annotations

import time

from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Background loop for syncing integrations periodically (currently: Proxmox)."

    def add_arguments(self, parser):
        parser.add_argument("--sleep", type=int, default=30, help="Sleep seconds between checks.")
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")

    def handle(self, *args, **opts):
        sleep_s = int(opts.get("sleep") or 30)
        org_id = opts.get("org_id")

        self.stdout.write(f"Starting integrations sync loop (sleep={sleep_s}s, org_id={org_id or 'ALL'})")
        while True:
            try:
                if org_id:
                    call_command("sync_integrations_once", org_id=int(org_id))
                else:
                    call_command("sync_integrations_once")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"sync loop error: {e}"))
            time.sleep(sleep_s)

