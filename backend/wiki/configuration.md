# Configuration

HomeGlue supports two configuration sources:

- **UI-backed settings (DB-backed)**: managed inside HomeGlue (superuser-only) and applied immediately.
- **Environment-backed settings (`.env`)**: used for bootstrapping and secrets; changing these typically requires a container recreate.

## Where To Configure Things

### UI (Recommended)

- System settings: `/app/admin/system/`
  - Base URL
  - IP allow/block lists
  - Trusted proxies (`X-Forwarded-For`)
  - CORS allowed origins + CSRF trusted origins
  - `ALLOWED_HOSTS` override
  - Re-auth TTL, webhook timeout, SMTP timeout
- Email settings: `/app/admin/email/`

### Environment (`.env`)

Use `.env` for:

- secrets (`HOMEGLUE_SECRET_KEY`, `HOMEGLUE_FERNET_KEY`, SMTP password if you prefer env-backed)
- database connection (`DATABASE_URL` / Postgres vars)
- port and debug mode (`HOMEGLUE_PORT`, `HOMEGLUE_DEBUG`)
- OIDC/SSO (currently env-backed; restart required)

After editing `.env`, apply changes with:

```bash
cd /opt/homeglue
docker compose up -d --force-recreate --no-deps web worker
```

## Reverse Proxy Checklist

If HomeGlue is behind a reverse proxy, configure (UI: `/app/admin/system/`):

- `ALLOWED_HOSTS` override to include your public hostname
- `CSRF Trusted Origins` for the public URL (e.g. `https://homeglue.example.com`)
- `Base URL` to the public URL
- If you use IP allowlists: enable `Trust X-Forwarded-For` and set trusted proxy CIDRs

## Secrets Note

Treat `.env` as sensitive, especially `HOMEGLUE_FERNET_KEY` (decrypts stored secrets).

