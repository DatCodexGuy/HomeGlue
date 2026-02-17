# HomeGlue

[![Release](https://img.shields.io/github/v/release/DatCodexGuy/HomeGlue)](https://github.com/DatCodexGuy/HomeGlue/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fdatcodexguy%2Fhomeglue-2496ed)](https://github.com/DatCodexGuy/HomeGlue/pkgs/container/homeglue)

Self-hosted IT documentation system inspired by IT Glue, focused on clean org-first tenancy, fast navigation, and solid day-to-day ops features.

## Why This Exists

HomeGlue started as a practical response to gaps (and friction) in existing IT documentation platforms for a homelab-first workflow.

It is also a real-world experiment in AI-assisted software delivery: this project was built end-to-end by prompting **Codex 5.3** with **zero manual code changes**. All implementation, iteration, and fixes were done via prompts, and the result exceeded expectations.

## Features

- Org-first tenancy (you must enter an org; no combined org view)
- Assets, configuration items, flexible assets
- Docs + templates + folders (Markdown supported)
- Password vault (Fernet-encrypted) + TOTP + SafeShare links
- Domains + SSL certificates (expiry tracking + public lookup)
- Notes (Markdown supported) + tags + custom fields
- Relationships (any-to-any, IT Glue-style)
- Files library (attachments + org uploads) with previews, folders, tags, bulk filing
- Workflows + notifications (hygiene + expiry reminders)
- Backups (manual + scheduled snapshots) + restore wizard (bundle validation + media extraction)
- Dark mode + quick palette + saved views + CSV import/export

## Quick Start

One-liner installer (installs to `/opt/homeglue`, creates `.env` if missing, pulls the latest Docker images):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

Open:

- App UI (login): `http://localhost:8080/` or `http://<LAN-IP>:8080/`
- Wiki (public): `http://localhost:8080/wiki/`
- API docs (Swagger): `http://localhost:8080/api/docs/`

Superuser credentials are stored in `/opt/homeglue/.env` after install.

## Updates

Update to the latest image:

```bash
cd /opt/homeglue
./scripts/update.sh
```

## Configuration

HomeGlue reads configuration from `.env` in the install directory (`/opt/homeglue/.env` by default).

Minimum required env vars:

- `HOMEGLUE_SECRET_KEY`
- `HOMEGLUE_FERNET_KEY` (Fernet base64 32-byte key)
- `POSTGRES_PASSWORD`

Recommended:

- `HOMEGLUE_ALLOWED_HOSTS`
- `HOMEGLUE_DEBUG=0` for anything beyond local dev

See `.env.example` for the full list.

## Documentation

- Public Wiki: `/wiki/`
- In-app Wiki: `/app/wiki/` (when logged in)
- Wiki content source (shipped with the image): `backend/wiki/`

## Development

Local development (build from source instead of pulling images):

```bash
HOMEGLUE_COMPOSE_FILE=docker-compose.dev.yml HOMEGLUE_BUILD=1 ./scripts/install.sh
```

## License

AGPL-3.0 (see `LICENSE`).

## Contributing

Issues and PRs are welcome. Please keep user-facing documentation in `backend/wiki/` and keep any internal notes out of the repo.
