# HomeGlue

Self-hosted IT documentation system inspired by IT Glue, focused on clean org-first tenancy, fast navigation, and solid “day-to-day ops” features.

## Highlights

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

## Quick Start (Docker)

One-liner installer (installs to `/opt/homeglue`, creates `.env` if missing, pulls the latest Docker images):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

If the repo is private, install via SSH:

```bash
HOMEGLUE_REPO_URL=git@github.com:DatCodexGuy/HomeGlue.git \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

Manual setup (if you want full control):

```bash
mkdir -p /opt/homeglue/scripts
cd /opt/homeglue
curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/.env.example -o .env.example
curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/install.sh -o scripts/install.sh
chmod +x scripts/install.sh
./scripts/install.sh
```

If you want to run on a different port, set `HOMEGLUE_PORT` in `.env` (default: 8080).

Open:

- App UI (login): `http://localhost:${HOMEGLUE_PORT:-8080}/`
- Wiki (public): `http://localhost:${HOMEGLUE_PORT:-8080}/wiki/`
- API: `http://localhost:${HOMEGLUE_PORT:-8080}/api/`
- API docs (Swagger): `http://localhost:${HOMEGLUE_PORT:-8080}/api/docs/`

## Updates

To update HomeGlue after install:

```bash
cd /opt/homeglue
./scripts/update.sh
```

## Configuration

Minimum required env vars:

- `HOMEGLUE_SECRET_KEY`
- `HOMEGLUE_FERNET_KEY` (Fernet base64 32-byte key)
- `POSTGRES_PASSWORD`

Recommended:

- `HOMEGLUE_ALLOWED_HOSTS`
- `HOMEGLUE_DEBUG=0` for anything beyond local dev

See `.env.example` for the full list.

## Key Concepts

- **Organization (org)**: top-level tenancy boundary. Users must be a member of an org to access its data.
- **Visibility/ACLs**: Docs and Passwords support org/admin/private/shared visibility rules; non-admins cannot see restricted objects or their attachments.
- **Relationships**: stored generically (ContentType/object_id) so anything can relate to anything within an org.

## Backups & Restore

- Backups are org snapshot zip bundles: `manifest.json` + `fixture.json` + `media/` binaries.
- The UI restore wizard supports uploading/validating a bundle and extracting `media/` into `MEDIA_ROOT`.
- Database restore is an operator action; safest approach is restoring into a fresh stack and running `loaddata` on `fixture.json`.

More details: see the in-app Wiki (Help -> Wiki) or `backend/wiki/backups.md`.

## Development Notes

- This repo is designed to be run via Docker Compose.
- Code is baked into images by default (only media is persisted in a volume).
- If you change Python code, rebuild: `docker compose up -d --build web worker`

## License

AGPL-3.0 (see `LICENSE`).

## Docs

- In-app Wiki content (ships with HomeGlue): `backend/wiki/`
- Note: `docs/` is intentionally not tracked in git; end-user documentation ships via `backend/wiki/`.
