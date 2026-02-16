# Audit Log and History

HomeGlue tracks changes to org data and important security events.

## Audit Log

The audit log UI is available at:

- `/app/audit/`

Features:

- filter by model/object/user
- human-readable summaries (intended; report issues if you see raw model keys)
- CSV export

## Recent Activity

Many detail pages include an `Activity` panel that shows recent events relevant to that object.

## Retention and Purge

Superusers can configure audit retention and purge old events from:

- `/app/admin/ops/`

These actions are gated behind re-authentication because they are high-risk operations.

## Version History and Restore

Some object types have version history and support restoring a previous version.

When available, you’ll see a `Versions` panel on the object detail page.

