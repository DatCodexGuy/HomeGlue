# Domains and SSL Certificates

HomeGlue tracks domain registrations and SSL certificates with expiry dates and reminders.

## Domains

Domains are org-scoped records with pragmatic fields:

- registrar
- DNS provider
- expiry date
- auto-renew (boolean)
- notes/tags/custom fields

### Public Lookup (RDAP)

When creating or editing a Domain, HomeGlue can attempt to auto-fill public info:

- registrar
- expiry date

UI actions:

- On the “New domain” form: click `Lookup`
- On the domain detail page: click `Refresh`

Notes:

- Private/internal domains often have no public RDAP data.
- Lookup is best-effort and will not overwrite fields you already filled unless you use `Refresh`.

## SSL Certificates

SSL certificates are org-scoped and can be linked to one or more Domains.

Fields tracked:

- common name
- issuer
- validity window (not before / not after)
- serial number
- SHA-256 fingerprint (when available)
- SANs (subject alternative names)
- notes/tags/custom fields

### Auto-Populate From Common Name

HomeGlue tries to fetch certificate metadata by connecting to the host and reading the TLS certificate.

Supported input formats:

- `example.com` (assumes port 443)
- `example.com:8443`
- `https://example.com` (host extracted)

UI actions:

- On the “New SSL certificate” form: click `Lookup`
- On the SSL certificate detail page: click `Refresh`

Fallback behavior:

- If direct TLS to the host is unreachable, HomeGlue will attempt a best-effort lookup via `crt.sh` (Certificate Transparency).

Notes:

- Some hosts do not expose the expected cert on the given port.
- Internal hosts may not be reachable from the HomeGlue server; in that case, enter fields manually.

