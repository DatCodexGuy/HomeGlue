from __future__ import annotations

import time

from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Background worker loop: integrations sync + workflows evaluation + recurring checklists."

    def add_arguments(self, parser):
        parser.add_argument("--sleep", type=int, default=30, help="Sleep seconds between checks.")
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")

    def handle(self, *args, **opts):
        sleep_s = int(opts.get("sleep") or 30)
        org_id = opts.get("org_id")
        self.stdout.write(f"Starting worker loop (sleep={sleep_s}s, org_id={org_id or 'ALL'})")

        while True:
            try:
                if org_id:
                    call_command("sync_integrations_once", org_id=int(org_id))
                    call_command("run_checklist_schedules_once", org_id=int(org_id))
                    call_command("run_workflows_once", org_id=int(org_id))
                    call_command("deliver_workflow_notifications_once", org_id=int(org_id))
                    call_command("run_backup_scheduler_once", org_id=int(org_id))
                    call_command("run_backups_once", org_id=int(org_id))
                else:
                    call_command("sync_integrations_once")
                    call_command("run_checklist_schedules_once")
                    call_command("run_workflows_once")
                    call_command("deliver_workflow_notifications_once")
                    call_command("run_backup_scheduler_once")
                    call_command("run_backups_once")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"worker loop error: {e}"))
            time.sleep(sleep_s)
