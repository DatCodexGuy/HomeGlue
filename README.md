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

One-liner installer (installs to `/opt/homeglue`, creates `.env` if missing):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

If the repo is private, install via SSH:

```bash
HOMEGLUE_REPO_URL=git@github.com:DatCodexGuy/HomeGlue.git \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

Install from git:

```bash
git clone https://github.com/DatCodexGuy/HomeGlue.git /opt/homeglue
cd /opt/homeglue
./scripts/install.sh
```

Manual setup (if you want full control):

```bash
cp .env.example .env
docker compose up -d --build
```

### Private Repo Install Notes

If the GitHub repo is private, the `raw.githubusercontent.com` one-liner will return `404` unless you authenticate.

Recommended private-repo flow:

- Clone via SSH: `git clone git@github.com:DatCodexGuy/HomeGlue.git /opt/homeglue`
- Run: `./scripts/install.sh`

`./scripts/install.sh` will now auto-install prerequisites like Docker (Debian/Ubuntu) if missing.

If you want to run on a different port, set `HOMEGLUE_PORT` in `.env` (default: 8080).

Open:

- App UI: `http://localhost:${HOMEGLUE_PORT:-8080}/app/`
- Admin: `http://localhost:${HOMEGLUE_PORT:-8080}/admin/`
- API: `http://localhost:${HOMEGLUE_PORT:-8080}/api/`
- API docs (Swagger): `http://localhost:${HOMEGLUE_PORT:-8080}/api/docs/`

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

More details: `docs/wiki/backups.md`

## Development Notes

- This repo is designed to be run via Docker Compose.
- Code is baked into images by default (only media is persisted in a volume).
- If you change Python code, rebuild: `docker compose up -d --build web worker`

## License

AGPL-3.0 (see `LICENSE`).

## Docs

- Public status: `docs/STATUS.md`
- IT Glue parity: `docs/PARITY_ITGLUE.md`
- Wiki content (source of truth): `backend/wiki/`
- Wiki content (mirrored for GitHub browsing): `docs/wiki/`
