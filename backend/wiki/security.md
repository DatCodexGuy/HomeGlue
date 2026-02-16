# Security

This page documents the security posture and key security-related features.

## IP Access Control

HomeGlue supports optional IP allowlist/blocklist enforcement for the entire app (UI + API).

Environment variables:

- `HOMEGLUE_IP_ALLOWLIST`: comma-separated CIDRs/IPs. If set, only these IPs are allowed.
- `HOMEGLUE_IP_BLOCKLIST`: comma-separated CIDRs/IPs. Always denied (even if in allowlist).

Examples:

```text
HOMEGLUE_IP_ALLOWLIST=10.0.0.0/24,192.168.1.10
HOMEGLUE_IP_BLOCKLIST=10.0.0.123/32
```

### Reverse Proxies (X-Forwarded-For)

By default HomeGlue does not trust `X-Forwarded-For`.

To trust it, you must explicitly enable it and define trusted proxy CIDRs:

```text
HOMEGLUE_TRUST_X_FORWARDED_FOR=true
HOMEGLUE_TRUSTED_PROXY_CIDRS=10.0.0.0/24
```

Only requests coming from a trusted proxy IP will use `X-Forwarded-For` for access control/audit.

## Single Sign-On (OIDC)

HomeGlue supports OIDC via `mozilla-django-oidc`.

Enable and configure:

```text
HOMEGLUE_OIDC_ENABLED=true
HOMEGLUE_OIDC_CLIENT_ID=...
HOMEGLUE_OIDC_CLIENT_SECRET=...
HOMEGLUE_OIDC_AUTHORIZATION_ENDPOINT=https://idp.example.com/oauth2/v1/authorize
HOMEGLUE_OIDC_TOKEN_ENDPOINT=https://idp.example.com/oauth2/v1/token
HOMEGLUE_OIDC_USER_ENDPOINT=https://idp.example.com/oauth2/v1/userinfo
HOMEGLUE_OIDC_JWKS_ENDPOINT=https://idp.example.com/oauth2/v1/keys
HOMEGLUE_OIDC_SIGN_ALGO=RS256
HOMEGLUE_OIDC_SCOPES=openid email profile
```

When enabled:

- `/oidc/` routes are registered
- Login page shows a “Sign in with SSO” option
- Users are created on first login (matched by email when available)

Memberships/roles are still managed inside HomeGlue.

## Re-authentication (Sensitive Actions)

HomeGlue requires a recent re-authentication for sensitive actions like:

- revealing passwords
- viewing OTP/TOTP codes
- enabling/rotating/disabling OTP/TOTP

### UI

The UI uses session-based re-auth. You will be prompted to confirm your password when needed.

### API

The API uses a short-lived re-auth token:

1. `POST /api/me/reauth/` with `{ "password": "..." }`
2. Add the token to sensitive requests:
   - `X-HomeGlue-Reauth: <token>`

### Configuration

- `HOMEGLUE_REAUTH_TTL_SECONDS` (default: `900`)

## Password Storage

Passwords are stored encrypted at rest using a Fernet key (`HOMEGLUE_FERNET_KEY`).

Important notes:

- Do not rotate `HOMEGLUE_FERNET_KEY` casually; you will lose the ability to decrypt existing secrets unless you implement a proper re-encryption migration.
- Treat `.env` as sensitive and store it securely (permissions, backups, secrets management).

## Sharing Sensitive Data (SafeShare)

HomeGlue supports restricted share links for passwords and files.

Typical controls:

- expiry
- one-time use
- passphrase requirement
- max-download limits (files)

Share links should be treated as secrets. Revoke them when no longer needed.
