# Checklists (Runbooks)

HomeGlue implements “checklists” as templates (runbooks) plus runs (execution instances).

## Checklist Templates

Checklist templates contain ordered items (steps). Templates can have tags, attachments, notes, relationships, and versions.

## Checklist Runs

Runs are created from a template and track execution state:

- Due date
- Assigned user
- Open/Done status
- Per-item completion tracking

Runs can also be linked to an object (optional).

## Checklist Schedules (Recurring)

Schedules create runs automatically on a simple cadence:

- “Every N days”
- `next_run_on` controls when the next run will be created
- Optional due date offset (`due_days`)

Schedules are processed by the background worker loop.

