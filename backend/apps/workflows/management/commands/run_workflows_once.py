from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.workflows.engine import run_due_rules


class Command(BaseCommand):
    help = "Evaluate due workflow rules once. Intended to be run in a loop."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        created = run_due_rules(org_id=int(org_id) if org_id else None)
        self.stdout.write(f"Workflows: notifications_created={created}")

