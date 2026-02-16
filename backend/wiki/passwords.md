# Passwords and Folders

Passwords are stored encrypted at rest (Fernet).

## Password Entries

Features:

- Username + URL + notes
- Tags
- Folders (nested)
- Attachments + relationships + notes
- Visibility / ACL (org/admins/private/shared)
- Optional TOTP (one-time password) generator

## Typical Workflow

1. Create the password entry (name + username + URL).
2. Put it in a folder (by client, system, or purpose).
3. Add OTP if the account uses 2FA.
4. Link it to:
   - the relevant Asset or Config Item
   - the relevant Doc runbook
5. Use SafeShare links when you must share access temporarily.

## Security Notes

- Password reveal and OTP viewing require re-authentication.
- Treat `.env` (and especially `HOMEGLUE_FERNET_KEY`) as sensitive.

## OTP / TOTP

You can enable a TOTP secret per password entry (for 2FA codes).

In the password detail page:

- Click `Enable OTP` to generate a new secret.
- Copy the Base32 secret into your authenticator app, or copy the `otpauth://` URL.
- HomeGlue will show the current 6-digit code and refresh it automatically.

Notes:

- OTP is protected by the same visibility/ACL rules as the password reveal.
- OTP and password reveal also require a recent re-authentication (password confirmation).
- Rotating OTP replaces the secret; your authenticator app must be updated.

## Import/Export

Passwords support CSV export and import. Import supports optional `folder` column and upserts by `(org, folder, name)`.

## SafeShare Links

Password entries can be shared via restricted links (expiry, one-time use).

Recommended usage:

- Use the shortest expiry that works.
- Revoke links when the job is done.
- Prefer creating a real user and adding them to the org for ongoing access.
