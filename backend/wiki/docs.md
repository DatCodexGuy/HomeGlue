# Documents and Templates

## Documents

Documents are org-scoped pages used for SOPs, internal notes, and knowledge base content.

Features:

- Templates (optional)
- Document folders (nested)
- Tags
- Attachments
- Notes
- Relationships
- Version history + restore
- Visibility / ACL (org/admins/private/shared)
- Flag/Unflag for “important” docs

## Markdown

Document bodies support Markdown.

Use Markdown for:

- runbooks (headings + ordered lists)
- checklists (task lists)
- inline code and code blocks (commands)

## Suggested Document Types

- “Network Overview”
- “Backups SOP”
- “Proxmox Upgrade Procedure”
- “Disaster Recovery Notes”
- “Service Runbooks” (DNS, DHCP, VPN, storage, monitoring)

## Templates

Templates are reusable document bodies. You can create docs from templates, and import/export templates via CSV.

## Folder Structure (Recommended)

Example structure that scales well:

- `Runbooks/`
- `Architecture/`
- `Vendors/`
- `Backups/`
- `Security/`
- `Projects/`

## Import/Export

Docs CSV import supports an optional `folder` column. Folder values can be a path like `Runbooks/Onboarding` and HomeGlue will create folders as needed.

## Version History and Restore

When available, use `Versions` on a document to:

- compare changes
- restore a previous version

Recommended policy:

- keep runbooks updated
- use versions as your change history instead of duplicating docs
