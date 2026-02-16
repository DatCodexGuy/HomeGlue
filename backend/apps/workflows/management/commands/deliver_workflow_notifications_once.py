from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.workflows.delivery import deliver_workflow_notifications_once


class Command(BaseCommand):
    help = "Deliver workflow notifications via email/webhooks once (best-effort). Intended to be run in a loop."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")
        parser.add_argument("--limit", type=int, default=200, help="Max notifications to consider per run.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        limit = int(opts.get("limit") or 200)
        res = deliver_workflow_notifications_once(org_id=int(org_id) if org_id else None, limit=limit)
        self.stdout.write(f"Workflows: delivered_email={res.get('email', 0)} delivered_webhook={res.get('webhook', 0)}")

