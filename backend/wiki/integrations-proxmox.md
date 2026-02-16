# Proxmox Integration

HomeGlue can sync inventory from Proxmox VE via API token.

## Setup

1. Create a Proxmox API token (e.g. `root@pam!homeglue`)
2. In HomeGlue, add a Proxmox connection:
   - `/app/integrations/`

## What Gets Synced

- Nodes
- Guests (VMs + containers), including on/off state and uptime when available
- Networks
- Storage
- Pools
- SDN objects when available (zones/vnets/etc.)

Synced guests can be mapped into Config Items.

