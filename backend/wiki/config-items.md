# Config Items

Config Items represent operational/infrastructure objects (hosts, VMs, containers, services).

## Fields (Core)

- Name
- Hostname
- Primary IP
- Operating system
- Notes + tags + attachments + relationships

## When To Use Config Items

Use Config Items for things that have:

- a hostname and/or IP
- an OS or “role” (hypervisor host, NAS OS, firewall OS, key services)
- operational runbooks (patching, backups, upgrade steps)

Pair them with Assets:

- Asset: “Dell R730”
- Config Item: “proxmox01”

Then link with Relationships.

## Creating Config Items

1. Go to:
   - `/app/config-items/`
2. Click `New config item`.
3. Fill the key operational identifiers:
   - hostname
   - primary IP
   - OS
4. Save.

Recommended next steps:

- attach a “build sheet” doc
- link the relevant password entries
- add workflows for hygiene (missing IP/hostname) and expiry (SSL, domain)

## Proxmox Mapping

If you use the Proxmox integration, synced guests can be mapped to Config Items.
