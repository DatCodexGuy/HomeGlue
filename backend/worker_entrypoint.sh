#!/usr/bin/env sh
set -eu

# Ensure migrations are applied before background sync starts (avoid web/worker races).
python manage.py migrate_with_lock

# Seed default workflow rules (idempotent; ensures expiry notifications work).
python manage.py seed_workflow_rules

# Default: check every 30 seconds. Only sync connections with sync_interval_minutes > 0.
SLEEP="${HOMEGLUE_SYNC_LOOP_SLEEP:-30}"

exec python manage.py worker_loop --sleep "$SLEEP"
