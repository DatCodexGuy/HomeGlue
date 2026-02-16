# Installation, Upgrade, and Uninstall

This page covers installing HomeGlue on a Docker host.

## Requirements

- Linux host with:
  - Docker Engine
  - Docker Compose plugin (`docker compose`)
- Inbound access to the app port (default `8080`).

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
```

What the bootstrap does:

- clones or downloads the repo
- creates `.env` with secure defaults (if missing)
- builds and starts the Docker stack
- runs migrations
- creates/updates the default superuser (credentials stored in `.env`)

After install:

- App: `http://<host>:<port>/app/`
- Login uses the superuser from `.env`

## Install From Git (Manual)

```bash
git clone git@github.com:DatCodexGuy/HomeGlue.git /opt/homeglue
cd /opt/homeglue
./scripts/install.sh
```

If you do not want to use `scripts/install.sh`, you can:

```bash
docker compose up -d --build
docker compose exec -T web python manage.py migrate --noinput
```

## Configuration Basics

HomeGlue reads configuration from `.env` in the repo root.

The most common settings:

- `HOMEGLUE_PORT` (host port, default `8080`)
- `HOMEGLUE_ALLOWED_HOSTS` (set this for your hostname/IP)
- `HOMEGLUE_BASE_URL` (optional; used for building absolute links in notifications)

## Upgrade

Upgrade is pull + rebuild + migrate.

```bash
cd /opt/homeglue
git pull
docker compose up -d --build
docker compose exec -T web python manage.py migrate --noinput
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

