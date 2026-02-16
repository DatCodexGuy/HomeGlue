# Files and Attachments

HomeGlue supports two related concepts:

- **Attachments**: files attached to a specific object (asset, doc, password, domain, etc.)
- **Files**: an org-level file library experience (folders, tags, bulk actions)

## Attachments

Most object detail pages include an `Attachments` panel.

You can:

- upload files
- download files (auth required)
- delete files

Attachments are stored under the server’s media directory (inside containers: `/data/media`).

## File Sharing (SafeShare Links)

HomeGlue can generate restricted share links for sensitive content (files and passwords).

Depending on the object type and configuration, share links can support:

- expiry
- one-time use
- passphrase requirement
- max-download limits

Always treat share links as sensitive and revoke them when no longer needed.

