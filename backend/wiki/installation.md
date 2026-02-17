# Installation, Upgrade, and Uninstall

This page covers installing HomeGlue on a Docker host.

## Requirements

- Linux host with:
  - Docker Engine
  - Docker Compose plugin (`docker compose`)
- Inbound access to the app port (default `8080`).

HomeGlue runs from a prebuilt Docker image (pulled from GHCR).

## Install Options

HomeGlue supports:

- One-liner bootstrap (recommended)
- Clone from Git and run Compose
- Raw `docker-compose.yml` usage (same as the above, just without the bootstrap helper)

## One-Liner Install (Recommended)

Installs into `/opt/homeglue` by default.

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

Common options:

```bash
# Install to a different directory
HOMEGLUE_DIR=/srv/homeglue bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"

# Choose a different port on the host (defaults to 8080)
HOMEGLUE_PORT=8090 bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"

# Run side-by-side with another HomeGlue install on the same host
# (changes the Docker Compose project name so container/volume names don't conflict)
HOMEGLUE_COMPOSE_PROJECT=homeglue_test HOMEGLUE_PORT=8091 HOMEGLUE_DIR=/opt/homeglue-test \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
```

What the bootstrap does:

- downloads the deployment files into `/opt/homeglue` (no git required)
- creates `.env` with secure defaults (if missing)
- pulls and starts the Docker stack
- runs migrations
- creates/updates the default superuser (credentials stored in `.env`)

After install:

- App (login): `http://<host>:<port>/`
- Login uses the superuser from `.env`

## Install From Git (Manual)

```bash
git clone git@github.com:DatCodexGuy/HomeGlue.git /opt/homeglue-src
cd /opt/homeglue-src
# Dev only:
HOMEGLUE_COMPOSE_FILE=docker-compose.dev.yml HOMEGLUE_BUILD=1 ./scripts/install.sh
```

Notes:

- `./scripts/install.sh` will auto-install prerequisites like Docker on Debian/Ubuntu if they are missing.
- To opt out of prerequisite installs, set: `HOMEGLUE_NO_PREREQS=1`.

If you do not want to use `scripts/install.sh`, you can:

```bash
docker compose up -d --build
docker compose exec -T web python manage.py migrate --noinput
```

## Configuration Basics

HomeGlue reads configuration from `.env` in the repo root, but many day-to-day settings can be configured from the UI.

The most common settings:

- `HOMEGLUE_PORT` (host port, default `8080`)
- `HOMEGLUE_ALLOWED_HOSTS` (set this for your hostname/IP)
- `HOMEGLUE_BASE_URL` (optional; used for building absolute links in notifications)

UI-based system settings (superuser-only):

- `/app/admin/system/` (Base URL, IP allow/block lists, proxy trust, CORS/CSRF origins)

See also:

- Public Wiki: `/wiki/`
- In-app Wiki: `/app/wiki/`
- Full configuration guide: `/wiki/configuration/`

## Upgrade

Recommended upgrade options:

- Re-run the one-liner bootstrap (safe; updates `/opt/homeglue` and runs the installer)
- Or run the local updater script: `/opt/homeglue/scripts/update.sh`
- For stable upgrades, pin `HOMEGLUE_IMAGE` to a release tag in `.env` (recommended).

Manual upgrade is pull images + restart + migrate.

```bash
cd /opt/homeglue
./scripts/update.sh
```

Notes:

- If you are using the one-liner install and did not change anything, the above is typically enough.
- Keep a snapshot backup before upgrading (see `Backups and Restore`).

## Uninstall

To remove containers but keep data volumes:

```bash
cd /opt/homeglue
docker compose down
```

To remove containers and volumes (this deletes your DB and uploaded media):

```bash
cd /opt/homeglue
docker compose down -v
```
