# Workflows and Notifications

Workflows evaluate rules on a schedule and create **Notifications**.

## Rules

Rule examples:

- Domain expiry
- SSL expiry
- Checklist runs overdue
- Config items missing primary IP

Rules are org-scoped and can be enabled/disabled.

## Notifications

Notifications are per-user and org-scoped.

## Delivery Channels

HomeGlue supports:

- Email delivery (optional)
- Webhook delivery (optional, org-scoped endpoints)

### Email (Environment Variables)

Email sending is controlled by these environment variables (see `homeglue/backend/homeglue/settings.py`):

- `HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED=true|false`
- `HOMEGLUE_EMAIL_BACKEND=console|smtp|smtp+tls|smtp+ssl`
- `HOMEGLUE_EMAIL_FROM=homeglue@yourdomain`
- SMTP settings (when using smtp):
  - `HOMEGLUE_SMTP_HOST`
  - `HOMEGLUE_SMTP_PORT`
  - `HOMEGLUE_SMTP_USER`
  - `HOMEGLUE_SMTP_PASSWORD`
  - `HOMEGLUE_SMTP_USE_TLS=true|false`
  - `HOMEGLUE_SMTP_USE_SSL=true|false`

### Webhooks

Configure webhook endpoints in the UI:

- `/app/workflows/webhooks/`

Payloads are signed (optional) with `X-HomeGlue-Signature: sha256=<hex>` when a secret is set.

