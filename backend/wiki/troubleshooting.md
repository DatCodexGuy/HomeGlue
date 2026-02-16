# Troubleshooting

This page collects the most common operational problems and how to diagnose them.

## Quick Health Checklist

1. Are containers up?

```bash
cd /opt/homeglue
docker compose ps
```

2. Can you see web logs?

```bash
docker compose logs --tail=200 web
```

3. Is the worker running?

```bash
docker compose logs --tail=200 worker
```

Also check `Admin -> Operations` for worker heartbeat:

- `/app/admin/ops/`

## “Blank pages” in the UI

Most often this is a template error, a JS error, or an unhandled server error.

Steps:

- Check the web container logs:

```bash
docker compose logs --tail=300 web
```

- If you’re behind a reverse proxy, confirm `HOMEGLUE_ALLOWED_HOSTS` includes the hostname you’re using.

## HTTP 500 errors

1. Check logs:

```bash
docker compose logs --tail=300 web
```

2. Confirm migrations are applied:

```bash
docker compose exec -T web python manage.py migrate --noinput
```

3. Restart after config changes:

```bash
docker compose up -d --build
```

## Can’t download attachments / files

If a file uploads but won’t download:

- verify the `media` volume is mounted and writable
- check web logs for permission errors

Common checks:

```bash
docker compose exec -T web sh -lc 'ls -la /data/media | head'
docker compose exec -T web sh -lc 'id && umask'
```

## Email notifications don’t send

- Ensure email is enabled and configured (UI or `.env`).
- Use the in-app test:
  - `/app/admin/email/` (DB-backed email settings + test send)
  - `/app/admin/config/` (read-only env config page + basic tests)

Then check:

```bash
docker compose logs --tail=300 worker
```

## IP access control blocks you unexpectedly

If you set an allowlist/blocklist and lock yourself out:

1. Edit `.env` and remove or correct:
   - `HOMEGLUE_IP_ALLOWLIST`
   - `HOMEGLUE_IP_BLOCKLIST`
2. Recreate containers:

```bash
docker compose up -d --build
```

If you are behind a reverse proxy:

- you must configure trusted proxies (`HOMEGLUE_TRUST_X_FORWARDED_FOR` + `HOMEGLUE_TRUSTED_PROXY_CIDRS`) or the app will evaluate the proxy IP instead of the client IP.
- if you see CSRF errors, configure CSRF trusted origins (UI: `/app/admin/system/`).

## Proxmox sync does not show anything

Check:

- connection URL is correct
- token is correct
- “Verify SSL” matches your Proxmox TLS setup
- worker is running (Proxmox sync happens in the worker)

Then run a manual sync from:

- `/app/admin/ops/`

And check worker logs:

```bash
docker compose logs --tail=300 worker
```
