# HomeGlue Documentation

HomeGlue is an IT documentation system inspired by IT Glue, optimized for a calmer, org-first workflow.

## Quick Links

- Wiki index: `/app/wiki/`
- App: `/app/`
- API: `/api/`
- API docs: `/api/docs/`
- Admin: `/admin/`

## Getting Started

Start here:

- Installation and upgrades: see `Installation, Upgrade, and Uninstall`
- Organizations and memberships: see `Organizations and Memberships`
- Admin and settings: see `Admin, Settings, and Operations`
- Security model: see `Security`
- Backups: see `Backups and Restore`

## Requirements

- Docker Engine + Docker Compose plugin
- A generated `HOMEGLUE_FERNET_KEY` (used for secrets encryption)

### One-Liner Install

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

This will (by default):

- install HomeGlue into `/opt/homeglue`
- create `.env` with secure defaults (if missing)
- build and start containers
- run database migrations
- create/update the default superuser (credentials are stored in `.env`)

Notes:

- If the repo is still private, install via `git clone` (below).
- To install to a different directory: `HOMEGLUE_DIR=/srv/homeglue bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"`

### Manual Install

1. Clone the repo onto your host
2. Create `.env` (in the repo root) with at least:

```text
HOMEGLUE_SECRET_KEY=change-me
HOMEGLUE_ALLOWED_HOSTS=*
HOMEGLUE_FERNET_KEY=your-fernet-key
POSTGRES_PASSWORD=change-me
```

3. Start the stack:

```bash
cd /opt/homeglue  # or wherever you cloned the repo
docker compose up -d --build
```

4. Run migrations + create a superuser:

```bash
docker compose exec -T web python manage.py migrate --noinput
DJANGO_SUPERUSER_USERNAME=admin DJANGO_SUPERUSER_EMAIL=admin@example.local DJANGO_SUPERUSER_PASSWORD=change-me \\
  docker compose exec -T web python manage.py createsuperuser --noinput
```

5. Log in:

- Web app: `/app/`
- Admin: `/admin/`

## Core Concepts

- **Org-first navigation**: you must enter an Organization before viewing org-scoped objects.
- **Org scoping** applies to UI and API. There are no combined cross-org views.
- **Roles**:
    - Superuser: global admin (can create orgs and access all)
    - Org admin/owner: manages org configuration (relationship types, custom field definitions, workflows)
    - Org member: day-to-day usage (assets, docs, passwords, checklists)

## Features (High Level)

- Inventory:
    - Assets
    - Config Items
    - Flexible Assets (custom types)
- Documentation:
    - Documents + Templates
    - Version history + restore
    - Attachments, notes, tags, relationships
    - Document flags
- Secrets:
    - Encrypted password entries
    - Password folders (nested)
    - Visibility/ACL (org/admins/private/shared)
- Domains / SSL:
    - Expiry tracking and linking
    - Public lookup (one-click "Lookup" on create)
- Checklists:
    - Templates (runbooks)
    - Runs (execution instances)
    - Schedules (basic recurring cadence)
- Workflows:
    - Rule engine + per-user notifications
    - Delivery via email (optional) and webhooks (optional)
- Integrations:
    - Proxmox sync (nodes, guests, storage, networks, etc.)
- API:
    - Token/JWT/session auth
    - Org-scoped endpoints

## Email Notifications (Optional)

Configure (recommended):

- `/app/admin/email/`

Or via `.env`:

```text
HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED=true
HOMEGLUE_EMAIL_BACKEND=smtp
HOMEGLUE_EMAIL_FROM=homeglue@yourdomain
HOMEGLUE_SMTP_HOST=smtp.yourdomain
HOMEGLUE_SMTP_PORT=587
HOMEGLUE_SMTP_USER=...
HOMEGLUE_SMTP_PASSWORD=...
HOMEGLUE_SMTP_USE_TLS=true
```

## Webhooks (Optional)

Configure webhook endpoints in the UI:

- `/app/workflows/webhooks/`

If a secret is set on the endpoint, payloads are signed:

- `X-HomeGlue-Signature: sha256=<hex>`

## Where To Configure Things

- User-level: `/app/account/`
- Org-level: `/app/settings/`
- System-level (superuser): `/app/admin/`
