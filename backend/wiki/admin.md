# Admin, Settings, and Operations

HomeGlue aims to avoid requiring the built-in admin site for normal operations.

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
- CORS allowed origins + CSRF trusted origins (reverse proxy support)
- `ALLOWED_HOSTS` override
- Re-auth TTL, webhook timeout, SMTP timeout

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

### What To Check After Running Ops Actions

- Workflow run:
  - `/app/notifications/` for new notifications
  - `/app/audit/` for an audit event describing the run
- Checklist schedules run:
  - `/app/checklist-runs/` for newly created runs
- Proxmox sync:
  - worker logs (`docker compose logs worker`)
  - integrations UI (`/app/integrations/`)
  - mapped Config Items (`/app/config-items/`)

## Admin Site (Optional)

The built-in admin site remains available at:

- `/admin/`

But the long-term goal is to not require it for normal operation.
