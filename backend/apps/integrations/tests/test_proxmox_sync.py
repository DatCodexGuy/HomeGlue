from __future__ import annotations

from django.test import TestCase

from apps.core.models import Organization
from apps.integrations.models import (
    ProxmoxConnection,
    ProxmoxGuest,
    ProxmoxGuestIP,
    ProxmoxNetwork,
    ProxmoxNode,
    ProxmoxPool,
    ProxmoxSdnVnet,
)
from apps.integrations.proxmox import sync_proxmox_connection
from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import Relationship, RelationshipType


class _FakeClient:
    def __init__(self, data: dict[str, object]):
        self.data = data

    def get(self, path: str, *, query=None):
        return self.data.get(path)


class ProxmoxSyncTests(TestCase):
    def test_sync_upserts_nodes_guests_networks(self):
        org = Organization.objects.create(name="Org 1")
        conn = ProxmoxConnection.objects.create(
            organization=org,
            name="PVE",
            base_url="https://pve.local:8006",
            token_id="root@pam!homeglue",
            verify_ssl=False,
            enabled=True,
        )
        conn.set_token_secret("secret")
        conn.save()

        fake = _FakeClient(
            {
                "/cluster/status": [{"type": "cluster", "name": "pve", "version": "8.0"}],
                "/pools": [{"poolid": "prod", "comment": "Production"}],
                "/pools/prod": {"poolid": "prod", "members": [{"type": "qemu", "vmid": 100}]},
                "/cluster/sdn/vnets": [{"vnet": "vnet0", "zone": "zone0", "tag": 42, "alias": "main"}],
                "/cluster/resources": [
                    {"type": "node", "node": "pve1", "status": "online", "maxcpu": 16, "maxmem": 123, "maxdisk": 456},
                    {"type": "qemu", "node": "pve1", "vmid": 100, "name": "vm1", "status": "running", "maxcpu": 4, "maxmem": 111, "tags": "web;prod", "pool": "prod"},
                    {"type": "lxc", "node": "pve1", "vmid": 200, "name": "ct1", "status": "stopped", "maxcpu": 2, "maxmem": 222},
                ],
                "/nodes/pve1/network": [
                    {"iface": "vmbr0", "type": "bridge", "address": "10.0.0.2", "netmask": "255.255.255.0"},
                ],
                "/nodes/pve1/storage": [
                    {"storage": "local", "type": "dir", "status": "available", "total": 100, "used": 40, "avail": 60},
                ],
                "/nodes/pve1/status": {"cpuinfo": {"model": "x"}},
                "/nodes/pve1/version": {"version": "8.1"},
                "/nodes/pve1/qemu/100/config": {"ipconfig0": "ip=10.0.0.10/24,gw=10.0.0.1", "ostype": "l26", "tags": "web;prod"},
                "/nodes/pve1/qemu/100/status/current": {"status": "running", "uptime": 123},
                "/nodes/pve1/lxc/200/config": {"net0": "name=eth0,bridge=vmbr0,ip=10.0.0.20/24"},
                "/nodes/pve1/lxc/200/status/current": {"status": "stopped", "uptime": 0},
                "/nodes/pve1/qemu/100/agent/network-get-interfaces": {
                    "result": [
                        {
                            "name": "eth0",
                            "ip-addresses": [{"ip-address": "10.0.0.99", "prefix": 24}],
                        }
                    ]
                },
                "/nodes/pve1/qemu/100/agent/get-host-name": {"result": "vm1.local"},
                "/nodes/pve1/qemu/100/agent/get-osinfo": {"result": {"name": "Debian GNU/Linux", "version": "12"}},
            }
        )

        res = sync_proxmox_connection(conn, client=fake)  # type: ignore[arg-type]
        self.assertTrue(res.ok, res.error)

        self.assertEqual(ProxmoxNode.objects.filter(connection=conn).count(), 1)
        self.assertEqual(ProxmoxGuest.objects.filter(connection=conn).count(), 2)
        self.assertEqual(ProxmoxNetwork.objects.filter(connection=conn).count(), 1)

        vm = ProxmoxGuest.objects.get(connection=conn, guest_type="qemu", vmid=100)
        self.assertIn("10.0.0.99/24", vm.ip_addrs)
        self.assertIsNotNone(vm.config_item_id)
        self.assertEqual(vm.ostype, "l26")
        self.assertIn("web", vm.proxmox_tags)
        self.assertEqual(vm.pool, "prod")
        self.assertEqual(vm.agent_hostname, "vm1.local")
        self.assertEqual((vm.agent_osinfo or {}).get("name"), "Debian GNU/Linux")
        self.assertEqual(ProxmoxGuestIP.objects.filter(guest=vm).count(), 1)

        ct = ProxmoxGuest.objects.get(connection=conn, guest_type="lxc", vmid=200)
        self.assertIn("10.0.0.20/24", ct.ip_addrs)
        self.assertIsNotNone(ct.config_item_id)

        self.assertEqual(ConfigurationItem.objects.filter(organization=org).count(), 3)
        self.assertTrue(ProxmoxPool.objects.filter(connection=conn, poolid="prod").exists())
        self.assertTrue(ProxmoxSdnVnet.objects.filter(connection=conn, vnet="vnet0").exists())

        # Assets are created for nodes + guests (best-effort).
        self.assertGreaterEqual(Asset.objects.filter(organization=org).count(), 3)
        self.assertTrue(ProxmoxNode.objects.filter(connection=conn, node="pve1").exclude(asset__isnull=True).exists())
        self.assertTrue(ProxmoxGuest.objects.filter(connection=conn, guest_type="qemu", vmid=100).exclude(asset__isnull=True).exists())

        # Nodes also map into configuration items (and guests are linked as Hosted On).
        self.assertTrue(ProxmoxNode.objects.filter(connection=conn, node="pve1").exclude(config_item__isnull=True).exists())
        self.assertTrue(RelationshipType.objects.filter(organization=org, name="Hosted On").exists())
        self.assertEqual(Relationship.objects.filter(organization=org, relationship_type__name="Hosted On").count(), 4)

        # Asset <-> CI linking exists for node + guests.
        self.assertTrue(RelationshipType.objects.filter(organization=org, name="Linked To").exists())
        self.assertGreaterEqual(Relationship.objects.filter(organization=org, relationship_type__name="Linked To").count(), 3)

    def test_sync_records_status_when_connection_disabled(self):
        org = Organization.objects.create(name="Org 1")
        conn = ProxmoxConnection.objects.create(
            organization=org,
            name="PVE",
            base_url="https://pve.local:8006",
            token_id="root@pam!homeglue",
            verify_ssl=False,
            enabled=False,
        )
        conn.set_token_secret("secret")
        conn.save()

        res = sync_proxmox_connection(conn, client=_FakeClient({}))  # type: ignore[arg-type]
        self.assertFalse(res.ok)

        conn.refresh_from_db()
        self.assertIsNotNone(conn.last_sync_at)
        self.assertFalse(conn.last_sync_ok)
        self.assertIn("disabled", (conn.last_sync_error or "").lower())
