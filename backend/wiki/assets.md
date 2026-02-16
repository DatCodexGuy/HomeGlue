# Assets and Inventory

HomeGlue tracks inventory in a few different ways:

- **Assets**: physical or logical things (servers, laptops, firewalls, printers, etc.)
- **Config Items**: configuration/infrastructure items (hosts, services, VMs/containers, etc.)
- **Flexible Assets**: user-defined types for structured data that doesn’t fit the built-in models

## Common Features

- Tags
- Attachments
- Notes
- Relationships (link anything to anything)
- Custom fields (org-admin defines; members fill values)
- Archive/restore (soft-delete)

## Typical Workflow

Recommended pattern:

1. Create an Asset for the physical thing (server, firewall, switch).
2. Create a Config Item for the OS/service running on it (hypervisor host, router OS, key VM).
3. Link them using Relationships (for example “Hosts / Runs On”).
4. Attach:
   - diagrams
   - exports (config backups)
   - photos/serial labels
5. Add a Doc runbook and link it to the Asset/Config Item.

## Creating Assets

1. Go to:
   - `/app/assets/`
2. Click `New asset`.
3. Fill the key identifiers:
   - name
   - type
   - serial number (if applicable)
4. Save.

Then (recommended):

- add tags
- add notes (Markdown supported)
- add attachments (warranty PDFs, config exports)
- link relationships to relevant docs, passwords, and other objects

## Flexible Assets (Structured Custom Types)

Use Flexible Assets when you want a repeatable, structured record type that HomeGlue does not provide out of the box.

Examples:

- “UPS” tracking
- “ISP Circuit” tracking
- “Software License” tracking
- “VLAN” tracking (until a dedicated network module exists)

## Archive / Restore

Archive is a soft-delete:

- relationships, notes, attachments remain
- archived items are hidden from normal lists

Restore is available to org admins/owners.

## CSV Import/Export

Most list pages have Export CSV and Import CSV actions for bulk changes.
