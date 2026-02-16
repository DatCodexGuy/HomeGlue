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
