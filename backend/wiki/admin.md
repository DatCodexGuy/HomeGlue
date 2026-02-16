# Admin, Settings, and Operations

HomeGlue aims to avoid requiring the Django admin UI for normal operations.

## Account vs Org vs System

- **Account** (`/app/account/`):
  - change your password
  - set your default org (used by the API)
  - create/rotate your personal API token
- **Org Settings** (`/app/settings/`):
  - manage org members and roles
  - configure org-level items (relationship types, workflows, custom fields)
- **System Admin** (superuser only, `/app/admin/`):
  - create orgs and users
  - manage memberships
  - view configuration and worker health
  - run operations (workflows/checklists/backups/proxmox sync)

## Super Admin Dashboard (Superuser Only)

Go to:

- `/app/admin/`

From there you can:

- create organizations
- create users
- add users to orgs and assign roles
- manage system-level settings and operations

## System Settings (DB-backed, Superuser Only)

Go to:

- `/app/admin/system/`

Currently supports:

- Base URL (used to generate absolute links in notifications)
- IP allowlist/blocklist
- Trusted proxies settings for `X-Forwarded-For`

Secrets are intentionally kept out of DB-backed settings; use `.env` for secrets.

## Config and Status (Superuser Only)

Go to:

- `/app/admin/config/`

Shows:

- effective config values (secrets are masked)
- email configuration status
- OIDC enablement status
- basic host/security settings

Includes:

- “Send test email” action (if email is enabled)

## Operations (Superuser Only)

Go to:

- `/app/admin/ops/`

This page:

- shows worker heartbeat (to confirm the worker is running)
- provides per-org actions (you must select an org context)
  - run checklist schedules
  - run workflow rules
  - deliver notifications
  - sync Proxmox inventory

It also contains governance actions (reauth required) such as audit retention policy changes and purge-now.

## Django Admin (Optional)

The Django admin remains available at:

- `/admin/`

But the long-term goal is to not require it for normal operation.

