# Workflows and Notifications

Workflows evaluate rules on a schedule and create **Notifications**.

## Rules

Rule examples:

- Domain expiry
- SSL expiry
- Checklist runs overdue
- Config items missing primary IP
- Backup failures (recent)
- Proxmox sync stale

Rules are org-scoped and can be enabled/disabled.

## Setting Up Workflows (Recommended)

1. Go to:
   - `/app/workflows/`
2. Enable the rules you actually want.
3. Set your “days ahead” warning windows (where applicable).
4. Confirm notifications appear:
   - `/app/notifications/`

If you want email delivery, configure SMTP in `.env` and rebuild containers.
Alternatively (recommended), configure email in the UI:

- `/app/admin/email/`

## Notifications

Notifications are per-user and org-scoped.

Typical lifecycle:

- workflow creates a notification
- user acknowledges/resolves it
- issue is corrected (renew cert, rotate password, run checklist)

## Delivery Channels

HomeGlue supports:

- Email delivery (optional)
- Webhook delivery (optional, org-scoped endpoints)

### Email (Environment Variables)

Email can be configured in the UI:

- `/app/admin/email/`

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

## Running Workflows Manually (Superuser)

If you want to force a run (for example right after enabling a rule):

- `/app/admin/ops/`

Then check:

- `/app/notifications/`
- `/app/audit/` for operational events (manual runs, ops actions)

## Troubleshooting

For org admins, HomeGlue keeps an execution history and delivery history:

- Workflow runs: `/app/workflows/runs/`
- Delivery attempts (email/webhooks): `/app/workflows/delivery/`
