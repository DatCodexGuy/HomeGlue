from __future__ import annotations

from django.core.management import BaseCommand, call_command
from django.db import connection


class Command(BaseCommand):
    help = "Run migrations with a Postgres advisory lock to avoid multi-container races."

    def add_arguments(self, parser):
        parser.add_argument("--lock-id", type=int, default=512042, help="Advisory lock id (int).")

    def handle(self, *args, **options):
        lock_id = int(options.get("lock_id") or 512042)

        if connection.vendor != "postgresql":
            call_command("migrate", interactive=False)
            return

        with connection.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s);", [lock_id])
        try:
            call_command("migrate", interactive=False)
        finally:
            try:
                with connection.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s);", [lock_id])
            except Exception:
                # Best-effort unlock (connection close will release lock anyway).
                pass

