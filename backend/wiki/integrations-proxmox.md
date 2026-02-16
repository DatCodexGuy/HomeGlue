# Proxmox Integration

HomeGlue can sync inventory from Proxmox VE via API token.

## Setup

1. Create a Proxmox API token.
   - Example user/token: `homeglue@pve!homeglue`
2. Give the token read-only permissions that allow listing cluster resources.
   - The built-in Proxmox `PVEAuditor` role is usually enough for read-only inventory.
3. In HomeGlue, add a Proxmox connection:
   - `/app/integrations/`

Fields you’ll configure:

- base URL (for example `https://pve.example.local:8006`)
- token ID and token secret
- verify SSL (turn off only if you understand the risk)
- sync interval

## What Gets Synced

- Nodes
- Guests (VMs + containers), including on/off state and uptime when available
- Networks
- Storage
- Pools
- SDN objects when available (zones/vnets/etc.)

Synced guests can be mapped into Config Items.

## Running a Sync

Sync runs in the `worker` container.

Options:

- wait for the next interval
- run a manual sync from:
  - `/app/admin/ops/` (superuser only)

## Common Problems

- Nothing syncs:
  - confirm the worker is running
  - confirm the API token has enough privileges
  - confirm your Proxmox URL is reachable from the HomeGlue server
- SSL errors:
  - either install a proper certificate on Proxmox or disable verification for that connection

