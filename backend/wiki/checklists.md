# Checklists (Runbooks)

HomeGlue implements “checklists” as templates (runbooks) plus runs (execution instances).

## Checklist Templates

Checklist templates contain ordered items (steps). Templates can have tags, attachments, notes, relationships, and versions.

## Creating a Checklist Template

1. Go to:
   - `/app/checklists/`
2. Click `New checklist`.
3. Add items (steps).
4. Link the checklist to a relevant object (optional) using Relationships.

Recommended use cases:

- “Monthly patching”
- “Backup restore test”
- “UPS battery test”
- “Renew certs/domains review”

## Checklist Runs

Runs are created from a template and track execution state:

- Due date
- Assigned user
- Open/Done status
- Per-item completion tracking

Runs can also be linked to an object (optional).

## Creating a Run

1. Open a checklist template
2. Create a run
3. Assign an owner and a due date
4. Complete items over time

## Checklist Schedules (Recurring)

Schedules create runs automatically on a recurring cadence:

- Daily: every N days
- Weekly: every N weeks, on selected weekdays
- Monthly: every N months, on a specific day-of-month (or last day)

Key fields:

- `next_run_on` controls when the next run will be created
- Optional due date offset (`due_days`) sets the run due date relative to `scheduled_for`

Schedules are processed by the background worker loop.

## Troubleshooting Schedules

If schedules don’t create runs:

- confirm the worker is running (`/app/admin/ops/` shows heartbeat)
- check worker logs (`docker compose logs worker`)
