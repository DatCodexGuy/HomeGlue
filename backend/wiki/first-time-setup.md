# First-Time Setup (Recommended Path)

This walkthrough gets you from a fresh install to a usable HomeGlue instance.

## 1. Log In

1. Open the app:
   - `/app/`
2. Log in with the superuser created during install (stored in `.env`).

## 2. Create Your First Organization

1. Go to the super admin dashboard:
   - `/app/admin/`
2. Create an Organization.
3. Check “Add me as Owner” so you can administer it without extra steps.

## 3. Create Users and Add Them to the Org

1. In `/app/admin/`, create user accounts.
2. Open the org detail page from the org list and add members.
3. Assign roles:
   - Owners/Admins can manage org configuration and archive/restore objects.
   - Members can do day-to-day documentation work.

## 4. Enter the Organization

HomeGlue is org-first.

1. Go to:
   - `/app/`
2. Click your Organization to “enter” it.

You should now see org-scoped navigation (Assets, Docs, Passwords, etc).

## 5. Set Your Default Org (API Convenience)

1. Go to:
   - `/app/account/`
2. Set a Default Organization.

This is used by the API when an explicit org is not provided.

## 6. Add Proxmox (Optional but Recommended)

1. In the org, go to:
   - `/app/integrations/`
2. Add a Proxmox connection (base URL + token).
3. Run a manual sync:
   - `/app/admin/ops/` (superuser only)

Verify:

- Proxmox items appear under integrations.
- Mapped guests show up as Config Items.

## 7. Create Your First Core Records

Suggested minimal set:

- 1 Asset: your primary server or firewall
- 1 Config Item: your main hypervisor host or management VM
- 2-3 Docs: “Network Overview”, “Proxmox Notes”, “Backups SOP”
- 1 Password entry: a critical credential (with OTP if needed)
- 1 Domain and SSL certificate if you have any public services

Link things together using Relationships.

## 8. Configure Workflows (Reminders)

1. Go to:
   - `/app/workflows/`
2. Enable rules you care about:
   - Domain expiry
   - SSL expiry
   - Password rotation due
   - Checklist runs overdue

Verify notifications:

- `/app/notifications/`

## 9. Configure Backups

1. Go to:
   - `/app/backups/`
2. Create a snapshot.
3. Enable the automation policy (interval + keep newest N).

Download one snapshot and store it somewhere safe.

## 10. (Optional) Enable Email Notifications

1. Configure SMTP settings in `.env`
2. Recreate containers:

```bash
cd /opt/homeglue
docker compose up -d --build
```

3. Test:
   - `/app/admin/config/` (Send test email)

## Where To Verify Everything

- Worker health: `/app/admin/ops/`
- Audit: `/app/audit/`
- Backups: `/app/backups/`
- Proxmox sync: `/app/admin/ops/` and worker logs (`docker compose logs worker`)

