from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from django.db import transaction
from django.contrib.contenttypes.models import ContentType

from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import Relationship, RelationshipType, Tag

from .models import (
    ProxmoxCluster,
    ProxmoxConnection,
    ProxmoxGuest,
    ProxmoxGuestIP,
    ProxmoxNetwork,
    ProxmoxNode,
    ProxmoxPool,
    ProxmoxSdnSubnet,
    ProxmoxSdnVnet,
    ProxmoxSdnZone,
    ProxmoxStorage,
)


class ProxmoxApiError(RuntimeError):
    pass


@dataclass(frozen=True)
class SyncResult:
    ok: bool
    nodes: int
    guests: int
    networks: int
    error: str = ""


class ProxmoxClient:
    def __init__(self, *, base_url: str, token_id: str, token_secret: str, verify_ssl: bool):
        self.base_url = (base_url or "").rstrip("/")
        self.token_id = token_id
        self.token_secret = token_secret
        self.verify_ssl = bool(verify_ssl)

        if not self.base_url or not self.base_url.startswith("http"):
            raise ProxmoxApiError("Invalid base_url.")
        if not self.token_id or "!" not in self.token_id:
            raise ProxmoxApiError("Invalid token_id (expected user@realm!tokenname).")
        if not self.token_secret:
            raise ProxmoxApiError("Missing token_secret.")

        self._ssl_ctx = None
        if not self.verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, *, query: dict | None = None):
        qp = ""
        if query:
            qp = "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        url = f"{self.base_url}/api2/json{path}{qp}"
        req = urllib.request.Request(url, method=method.upper())
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", f"PVEAPIToken={self.token_id}={self.token_secret}")

        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=20) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            raise ProxmoxApiError(f"HTTP {e.code} for {path}: {body[:300]}") from e
        except Exception as e:
            raise ProxmoxApiError(f"Request failed for {path}: {e}") from e

        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise ProxmoxApiError(f"Invalid JSON from {path}") from e
        return payload.get("data")

    def get(self, path: str, *, query: dict | None = None):
        return self._request("GET", path, query=query)


def _safe_get(client: ProxmoxClient, path: str):
    try:
        return client.get(path)
    except Exception:
        return None


def _parse_agent_ips(agent_payload: dict) -> list[str]:
    """
    Parse QEMU guest agent network-get-interfaces output into a flat list of IP/CIDR strings.
    Best-effort; ignores loopback/link-local.
    """

    ips: list[str] = []
    if not isinstance(agent_payload, dict):
        return ips
    if not isinstance(agent_payload.get("result"), list):
        return ips
    for iface in agent_payload.get("result") or []:
        if not isinstance(iface, dict):
            continue
        addrs = iface.get("ip-addresses") or []
        if not isinstance(addrs, list):
            continue
        for a in addrs:
            if not isinstance(a, dict):
                continue
            ip = (a.get("ip-address") or "").strip()
            prefix = a.get("prefix")
            if not ip:
                continue
            # Drop loopback/link-local noise
            if ip.startswith("127.") or ip == "::1" or ip.startswith("169.254.") or ip.startswith("fe80:"):
                continue
            if prefix is not None and str(prefix).isdigit():
                ip = f"{ip}/{int(prefix)}"
            if ip not in ips:
                ips.append(ip)
    return ips


def _parse_ips_from_config(config: dict) -> list[str]:
    ips: list[str] = []
    if not isinstance(config, dict):
        return ips

    def _add(ip: str):
        ip = (ip or "").strip()
        if not ip:
            return
        if ip in {"dhcp", "dhcp6", "auto", "slaac"}:
            return
        # Drop loopback/link-local noise
        if ip.startswith("127.") or ip == "::1" or ip.startswith("169.254.") or ip.startswith("fe80:"):
            return
        if ip not in ips:
            ips.append(ip)

    # Try common cloud-init style keys: ipconfig0, ipconfig1, ...
    for k, v in list(config.items()):
        if not str(k).startswith("ipconfig"):
            continue
        s = str(v or "")
        # e.g. "ip=10.0.0.10/24,gw=10.0.0.1"
        for part in s.split(","):
            part = part.strip()
            if part.startswith("ip="):
                _add(part.split("=", 1)[1].strip())
            if part.startswith("ip6="):
                _add(part.split("=", 1)[1].strip())

    # Best-effort: look for "ip=" embedded in netX definitions.
    for k, v in list(config.items()):
        if not str(k).startswith("net"):
            continue
        s = str(v or "")
        if ("ip=" not in s) and ("ip6=" not in s):
            continue
        for chunk in s.split(","):
            chunk = chunk.strip()
            if chunk.startswith("ip="):
                _add(chunk.split("=", 1)[1].strip())
            if chunk.startswith("ip6="):
                _add(chunk.split("=", 1)[1].strip())

    # LXC-style keys sometimes show up as separate config keys.
    for k, v in list(config.items()):
        key = str(k or "").lower()
        if "ipv4" in key and "address" in key:
            _add(str(v or ""))
        if "ipv6" in key and "address" in key:
            _add(str(v or ""))

    return ips


def _as_ip(ip_cidr: str) -> str:
    # Convert "10.0.0.10/24" -> "10.0.0.10"
    s = (ip_cidr or "").strip()
    if "/" in s:
        return s.split("/", 1)[0].strip()
    return s


def _ensure_ci_for_guest(*, org, guest: ProxmoxGuest) -> None:
    """
    Best-effort mapping from Proxmox guests into Configuration Items.

    Rules:
    - If already linked, update a few basic fields.
    - Else create a new CI with a unique name and link it.
    """

    # If guest doesn't have a usable name, don't create noisy records.
    base_name = (guest.name or "").strip()
    if not base_name:
        return

    ci_type = ConfigurationItem.TYPE_VM if guest.guest_type == ProxmoxGuest.TYPE_QEMU else ConfigurationItem.TYPE_CONTAINER
    primary_ip = None
    if guest.ip_addrs:
        ip0 = _as_ip(str(guest.ip_addrs[0]))
        if ip0:
            primary_ip = ip0

    tag, _ = Tag.objects.get_or_create(organization=org, name="synced:proxmox")

    if guest.config_item_id:
        ci = guest.config_item
        if not ci:
            guest.config_item_id = None
            guest.save(update_fields=["config_item", "updated_at"])
            return
        changed = False
        if ci.ci_type != ci_type:
            ci.ci_type = ci_type
            changed = True
        if primary_ip and (ci.primary_ip is None or str(ci.primary_ip) != primary_ip):
            ci.primary_ip = primary_ip
            changed = True
        if not ci.hostname:
            # Keep conservative: don't overwrite hostname if user set one.
            ci.hostname = base_name
            changed = True
        if not ci.operating_system:
            # Best-effort fill OS from guest agent metadata; otherwise keep blank.
            osinfo = guest.agent_osinfo or {}
            if isinstance(osinfo, dict):
                os_name = (osinfo.get("name") or "").strip()
                os_ver = (osinfo.get("version") or "").strip()
                if os_name and os_ver:
                    ci.operating_system = f"{os_name} {os_ver}"[:200]
                    changed = True
                elif os_name:
                    ci.operating_system = str(os_name)[:200]
                    changed = True
        # Add a small marker note once.
        marker = f"[proxmox] {guest.connection.name} {guest.guest_type}:{guest.vmid} node={guest.node}".strip()
        if marker not in (ci.notes or ""):
            ci.notes = ((ci.notes or "").strip() + ("\n" if (ci.notes or "").strip() else "") + marker).strip()
            changed = True
        if changed:
            ci.save()
        ci.tags.add(tag)
        return

    # Create new
    name = base_name
    if ConfigurationItem.objects.filter(organization=org, name=name).exists():
        name = f"{base_name} (pve {guest.vmid})"
    if ConfigurationItem.objects.filter(organization=org, name=name).exists():
        name = f"{base_name} (pve {guest.vmid} {guest.guest_type})"

    ci = ConfigurationItem.objects.create(
        organization=org,
        name=name[:200],
        ci_type=ci_type,
        hostname=base_name[:200],
        primary_ip=primary_ip,
        notes=f"[proxmox] {guest.connection.name} {guest.guest_type}:{guest.vmid} node={guest.node}".strip(),
    )
    ci.tags.add(tag)
    guest.config_item = ci
    guest.save(update_fields=["config_item", "updated_at"])


def _ensure_ci_for_node(*, org, node: ProxmoxNode) -> None:
    """
    Best-effort mapping from Proxmox nodes into Configuration Items.
    """

    base_name = (node.node or "").strip()
    if not base_name:
        return

    tag, _ = Tag.objects.get_or_create(organization=org, name="synced:proxmox")
    marker = f"[proxmox] {node.connection.name} node={node.node}".strip()

    if node.config_item_id:
        ci = node.config_item
        if not ci:
            node.config_item_id = None
            node.save(update_fields=["config_item", "updated_at"])
            return
        changed = False
        if ci.ci_type != ConfigurationItem.TYPE_SERVER:
            ci.ci_type = ConfigurationItem.TYPE_SERVER
            changed = True
        if not ci.hostname:
            ci.hostname = base_name[:200]
            changed = True
        if not ci.operating_system:
            ci.operating_system = "Proxmox VE"
            changed = True
        if marker not in (ci.notes or ""):
            ci.notes = ((ci.notes or "").strip() + ("\n" if (ci.notes or "").strip() else "") + marker).strip()
            changed = True
        if changed:
            ci.save()
        ci.tags.add(tag)
        return

    # Create new (avoid hijacking an existing human-made record with the same name).
    name = base_name
    if ConfigurationItem.objects.filter(organization=org, name=name).exists():
        name = f"{base_name} (pve node)"
    if ConfigurationItem.objects.filter(organization=org, name=name).exists():
        name = f"{base_name} (pve node {node.connection_id})"

    ci = ConfigurationItem.objects.create(
        organization=org,
        name=name[:200],
        ci_type=ConfigurationItem.TYPE_SERVER,
        hostname=base_name[:200],
        operating_system="Proxmox VE",
        notes=marker,
    )
    ci.tags.add(tag)
    node.config_item = ci
    node.save(update_fields=["config_item", "updated_at"])


def _ensure_asset_for_guest(*, org, guest: ProxmoxGuest) -> None:
    base_name = (guest.name or "").strip()
    if not base_name:
        return

    tag, _ = Tag.objects.get_or_create(organization=org, name="synced:proxmox")
    marker = f"[proxmox] {guest.connection.name} {guest.guest_type}:{guest.vmid} node={guest.node}".strip()
    desired_type = Asset.TYPE_SERVER if guest.guest_type == ProxmoxGuest.TYPE_QEMU else Asset.TYPE_OTHER

    asset = guest.asset
    if not asset:
        asset = Asset.objects.filter(organization=org, name=base_name, archived_at__isnull=True).first()
    created = False
    if not asset:
        asset = Asset.objects.create(
            organization=org,
            name=base_name[:200],
            asset_type=desired_type,
            manufacturer="Proxmox",
            model="VM" if guest.guest_type == ProxmoxGuest.TYPE_QEMU else "Container",
            notes=marker,
        )
        created = True

    changed = False
    if marker not in (asset.notes or ""):
        asset.notes = ((asset.notes or "").strip() + ("\n" if (asset.notes or "").strip() else "") + marker).strip()
        changed = True
    # Only fill these if blank (avoid clobbering user-provided data).
    if created and asset.asset_type != desired_type:
        asset.asset_type = desired_type
        changed = True
    if not asset.manufacturer:
        asset.manufacturer = "Proxmox"
        changed = True
    if not asset.model:
        asset.model = "VM" if guest.guest_type == ProxmoxGuest.TYPE_QEMU else "Container"
        changed = True
    if changed:
        asset.save()
    asset.tags.add(tag)

    if guest.asset_id != asset.id:
        guest.asset = asset
        guest.save(update_fields=["asset", "updated_at"])


def _ensure_asset_for_node(*, org, node: ProxmoxNode) -> None:
    base_name = (node.node or "").strip()
    if not base_name:
        return

    tag, _ = Tag.objects.get_or_create(organization=org, name="synced:proxmox")
    marker = f"[proxmox] {node.connection.name} node={node.node}".strip()

    asset = node.asset
    if not asset:
        asset = Asset.objects.filter(organization=org, name=base_name, archived_at__isnull=True).first()
    created = False
    if not asset:
        asset = Asset.objects.create(
            organization=org,
            name=base_name[:200],
            asset_type=Asset.TYPE_SERVER,
            manufacturer="Proxmox",
            model="Node",
            notes=marker,
        )
        created = True

    changed = False
    if marker not in (asset.notes or ""):
        asset.notes = ((asset.notes or "").strip() + ("\n" if (asset.notes or "").strip() else "") + marker).strip()
        changed = True
    if created and asset.asset_type != Asset.TYPE_SERVER:
        asset.asset_type = Asset.TYPE_SERVER
        changed = True
    if not asset.manufacturer:
        asset.manufacturer = "Proxmox"
        changed = True
    if not asset.model:
        asset.model = "Node"
        changed = True
    if changed:
        asset.save()
    asset.tags.add(tag)

    if node.asset_id != asset.id:
        node.asset = asset
        node.save(update_fields=["asset", "updated_at"])


def _ensure_hosted_on_relationship(*, org, guest: ProxmoxGuest, node: ProxmoxNode | None) -> None:
    if not guest.config_item_id or not node or not node.config_item_id:
        return

    rt, _ = RelationshipType.objects.get_or_create(
        organization=org,
        name="Hosted On",
        defaults={"inverse_name": "Hosts", "symmetric": False},
    )
    ct = ContentType.objects.get_for_model(ConfigurationItem)
    Relationship.objects.get_or_create(
        organization=org,
        relationship_type=rt,
        source_content_type=ct,
        source_object_id=str(guest.config_item_id),
        target_content_type=ct,
        target_object_id=str(node.config_item_id),
        defaults={"notes": f"[proxmox] {guest.connection.name}"},
    )


def _parse_tags(raw: str) -> list[str]:
    s = (raw or "").strip()
    if not s:
        return []
    # Proxmox uses ";" for tags, but accept commas as well.
    parts = []
    for chunk in s.replace(",", ";").split(";"):
        t = chunk.strip()
        if t and t not in parts:
            parts.append(t)
    return parts[:50]


def _upsert_ip_history(*, guest: ProxmoxGuest, ips: list[str], source: str) -> None:
    if not ips:
        return
    for ip in ips[:50]:
        if not ip:
            continue
        ProxmoxGuestIP.objects.update_or_create(guest=guest, ip=str(ip)[:128], defaults={"source": source})


@transaction.atomic
def sync_proxmox_connection(conn: ProxmoxConnection, *, client: ProxmoxClient | None = None) -> SyncResult:
    """
    Pull inventory from Proxmox and upsert our local snapshot tables.

    MVP strategy:
    - cluster/resources for nodes + guests (qemu/lxc) and their resource figures
    - per-node network list
    - per-guest config to extract ipconfig/net hints (best-effort)
    """

    # Even for disabled connections, record the attempted sync so the UI doesn't
    # misleadingly show "never synced".
    if not conn.enabled:
        conn.last_sync_at = datetime.now(tz=timezone.utc)
        conn.last_sync_ok = False
        conn.last_sync_error = "Connection disabled."
        conn.save(update_fields=["last_sync_at", "last_sync_ok", "last_sync_error", "updated_at"])
        return SyncResult(ok=False, nodes=0, guests=0, networks=0, error="Connection disabled.")

    try:
        client = client or ProxmoxClient(
            base_url=conn.base_url,
            token_id=conn.token_id,
            token_secret=conn.get_token_secret(),
            verify_ssl=conn.verify_ssl,
        )

        # Cluster status snapshot (useful for cluster name/version/quorum).
        cluster = client.get("/cluster/status") or []
        ProxmoxCluster.objects.update_or_create(connection=conn, defaults={"raw": {"status": cluster}})

        # Pools (optional)
        pools = _safe_get(client, "/pools")
        seen_pools = set()
        if isinstance(pools, list):
            for p in pools:
                if not isinstance(p, dict):
                    continue
                pid = (p.get("poolid") or "").strip()
                if not pid:
                    continue
                seen_pools.add(pid)
                detail = _safe_get(client, f"/pools/{urllib.parse.quote(pid)}") or {}
                ProxmoxPool.objects.update_or_create(
                    connection=conn,
                    poolid=pid,
                    defaults={
                        "comment": (p.get("comment") or p.get("remark") or "")[:5000],
                        "detail_raw": detail if isinstance(detail, (dict, list)) else {},
                    },
                )
            ProxmoxPool.objects.filter(connection=conn).exclude(poolid__in=list(seen_pools)).delete()

        # SDN (optional; may not exist depending on Proxmox version/config)
        zones = _safe_get(client, "/cluster/sdn/zones")
        seen_zones = set()
        if isinstance(zones, list):
            for z in zones:
                if not isinstance(z, dict):
                    continue
                zid = (z.get("zone") or z.get("name") or "").strip()
                if not zid:
                    continue
                seen_zones.add(zid)
                ProxmoxSdnZone.objects.update_or_create(
                    connection=conn,
                    zone=zid,
                    defaults={"kind": (z.get("type") or z.get("kind") or "")[:64], "raw": z},
                )
            ProxmoxSdnZone.objects.filter(connection=conn).exclude(zone__in=list(seen_zones)).delete()

        vnets = _safe_get(client, "/cluster/sdn/vnets")
        seen_vnets = set()
        if isinstance(vnets, list):
            for v in vnets:
                if not isinstance(v, dict):
                    continue
                vid = (v.get("vnet") or v.get("name") or "").strip()
                if not vid:
                    continue
                seen_vnets.add(vid)
                tag = v.get("tag")
                tag = int(tag) if str(tag).isdigit() else None
                ProxmoxSdnVnet.objects.update_or_create(
                    connection=conn,
                    vnet=vid,
                    defaults={
                        "zone": (v.get("zone") or "")[:200],
                        "alias": (v.get("alias") or v.get("comment") or "")[:200],
                        "tag": tag,
                        "raw": v,
                    },
                )
            ProxmoxSdnVnet.objects.filter(connection=conn).exclude(vnet__in=list(seen_vnets)).delete()

        subnets = _safe_get(client, "/cluster/sdn/subnets")
        seen_subnets = set()
        if isinstance(subnets, list):
            for s in subnets:
                if not isinstance(s, dict):
                    continue
                sid = (s.get("subnet") or s.get("cidr") or "").strip()
                if not sid:
                    continue
                seen_subnets.add(sid)
                ProxmoxSdnSubnet.objects.update_or_create(
                    connection=conn,
                    subnet=sid,
                    defaults={
                        "vnet": (s.get("vnet") or "")[:200],
                        "gateway": (s.get("gateway") or "")[:64],
                        "raw": s,
                    },
                )
            ProxmoxSdnSubnet.objects.filter(connection=conn).exclude(subnet__in=list(seen_subnets)).delete()

        resources = client.get("/cluster/resources") or []
        if not isinstance(resources, list):
            raise ProxmoxApiError("Unexpected /cluster/resources response.")

        # Nodes
        node_rows = [r for r in resources if isinstance(r, dict) and r.get("type") == "node" and r.get("node")]
        seen_nodes = set()
        node_obj_by_name: dict[str, ProxmoxNode] = {}
        for r in node_rows:
            node = str(r.get("node"))
            seen_nodes.add(node)
            status_raw = _safe_get(client, f"/nodes/{urllib.parse.quote(node)}/status") or {}
            version_raw = _safe_get(client, f"/nodes/{urllib.parse.quote(node)}/version") or {}
            node_obj, _ = ProxmoxNode.objects.update_or_create(
                connection=conn,
                node=node,
                defaults={
                    "status": (r.get("status") or "")[:32],
                    "cpu": r.get("cpu"),
                    "maxcpu": r.get("maxcpu"),
                    "mem": r.get("mem"),
                    "maxmem": r.get("maxmem"),
                    "disk": r.get("disk"),
                    "maxdisk": r.get("maxdisk"),
                    "uptime": r.get("uptime"),
                    "raw": r,
                    "status_raw": status_raw if isinstance(status_raw, (dict, list)) else {},
                    "version_raw": version_raw if isinstance(version_raw, (dict, list)) else {},
                },
            )
            # Map into "real" HomeGlue records.
            _ensure_asset_for_node(org=conn.organization, node=node_obj)
            _ensure_ci_for_node(org=conn.organization, node=node_obj)
            node_obj_by_name[node] = node_obj
        ProxmoxNode.objects.filter(connection=conn).exclude(node__in=list(seen_nodes)).delete()

        # Guests
        guest_rows = [r for r in resources if isinstance(r, dict) and r.get("type") in {"qemu", "lxc"} and r.get("vmid")]
        seen_guests = set()
        for r in guest_rows:
            gtype = str(r.get("type"))
            vmid = int(r.get("vmid"))
            seen_guests.add((gtype, vmid))
            node = str(r.get("node") or "")
            name = str(r.get("name") or "")

            config = {}
            status_current = {}
            if node:
                try:
                    config = client.get(f"/nodes/{urllib.parse.quote(node)}/{gtype}/{vmid}/config") or {}
                    if not isinstance(config, dict):
                        config = {}
                except Exception:
                    config = {}
                try:
                    status_current = client.get(f"/nodes/{urllib.parse.quote(node)}/{gtype}/{vmid}/status/current") or {}
                    if not isinstance(status_current, dict):
                        status_current = {}
                except Exception:
                    status_current = {}

            # Prefer agent-derived IPs for running QEMU guests; fall back to config hints.
            ips = []
            st = str(status_current.get("status") or r.get("status") or "")
            ip_source = ProxmoxGuestIP.SOURCE_CONFIG
            # Preserve agent metadata between syncs if we can't refresh it (e.g. guest is stopped).
            existing_guest = ProxmoxGuest.objects.filter(connection=conn, guest_type=gtype, vmid=vmid).only("agent_hostname", "agent_osinfo").first()
            agent_hostname = existing_guest.agent_hostname if existing_guest else ""
            agent_osinfo = existing_guest.agent_osinfo if existing_guest else {}
            if gtype == "qemu" and st == "running" and node:
                try:
                    agent = client.get(f"/nodes/{urllib.parse.quote(node)}/qemu/{vmid}/agent/network-get-interfaces")
                    if isinstance(agent, dict):
                        ips = _parse_agent_ips(agent)
                        if ips:
                            ip_source = ProxmoxGuestIP.SOURCE_AGENT
                except Exception:
                    ips = []
                # Best-effort: enrich with hostname/osinfo when agent is available.
                try:
                    hn = client.get(f"/nodes/{urllib.parse.quote(node)}/qemu/{vmid}/agent/get-host-name")
                    if isinstance(hn, dict):
                        hname = (hn.get("result") or "").strip()
                        if hname:
                            agent_hostname = str(hname)[:255]
                except Exception:
                    pass
                try:
                    osinfo = client.get(f"/nodes/{urllib.parse.quote(node)}/qemu/{vmid}/agent/get-osinfo")
                    if isinstance(osinfo, dict) and isinstance(osinfo.get("result"), dict):
                        agent_osinfo = osinfo.get("result") or {}
                except Exception:
                    pass
            if not ips:
                ips = _parse_ips_from_config(config)

            proxmox_tags = _parse_tags(str(config.get("tags") or r.get("tags") or ""))
            ostype = str(config.get("ostype") or status_current.get("ostype") or "")[:64]
            pool = str(r.get("pool") or config.get("pool") or "")[:200]

            ProxmoxGuest.objects.update_or_create(
                connection=conn,
                guest_type=gtype,
                vmid=vmid,
                defaults={
                    "node": node,
                    "name": name,
                    "status": (status_current.get("status") or r.get("status") or "")[:32],
                    "cpu": r.get("cpu"),
                    "maxcpu": r.get("maxcpu"),
                    "mem": r.get("mem"),
                    "maxmem": r.get("maxmem"),
                    "disk": r.get("disk"),
                    "maxdisk": r.get("maxdisk"),
                    "uptime": status_current.get("uptime") if status_current else r.get("uptime"),
                    "ip_addrs": ips,
                    "proxmox_tags": proxmox_tags,
                    "ostype": ostype,
                    "pool": pool,
                    "agent_hostname": agent_hostname,
                    "agent_osinfo": agent_osinfo if isinstance(agent_osinfo, dict) else {},
                    "raw": {"resource": r, "status_current": status_current},
                    "config_raw": config,
                },
            )
            guest_obj = (
                ProxmoxGuest.objects.filter(connection=conn, guest_type=gtype, vmid=vmid)
                .select_related("config_item", "asset")
                .first()
            )
            if guest_obj:
                _upsert_ip_history(guest=guest_obj, ips=ips, source=ip_source)
                _ensure_asset_for_guest(org=conn.organization, guest=guest_obj)
                _ensure_ci_for_guest(org=conn.organization, guest=guest_obj)
                host_node = node_obj_by_name.get(node) if node else None
                if not host_node and node:
                    host_node = ProxmoxNode.objects.filter(connection=conn, node=node).select_related("config_item").first()
                _ensure_hosted_on_relationship(org=conn.organization, guest=guest_obj, node=host_node)

        # Remove missing guests
        existing = list(ProxmoxGuest.objects.filter(connection=conn).values_list("guest_type", "vmid"))
        to_delete = [(t, v) for (t, v) in existing if (t, v) not in seen_guests]
        for t, v in to_delete:
            ProxmoxGuest.objects.filter(connection=conn, guest_type=t, vmid=v).delete()

        # Networks + storages
        seen_nets = set()
        seen_stor = set()
        for node in seen_nodes:
            nets = client.get(f"/nodes/{urllib.parse.quote(node)}/network") or []
            if not isinstance(nets, list):
                continue
            for n in nets:
                if not isinstance(n, dict):
                    continue
                iface = (n.get("iface") or "").strip()
                if not iface:
                    continue
                seen_nets.add((node, iface))
                ProxmoxNetwork.objects.update_or_create(
                    connection=conn,
                    node=node,
                    iface=iface,
                    defaults={
                        "kind": (n.get("type") or n.get("kind") or "")[:64],
                        "address": (n.get("address") or "")[:64],
                        "netmask": (n.get("netmask") or "")[:64],
                        "gateway": (n.get("gateway") or "")[:64],
                        "raw": n,
                    },
                )

            stor = client.get(f"/nodes/{urllib.parse.quote(node)}/storage") or []
            if isinstance(stor, list):
                for s in stor:
                    if not isinstance(s, dict):
                        continue
                    sid = (s.get("storage") or "").strip()
                    if not sid:
                        continue
                    seen_stor.add((node, sid))
                    ProxmoxStorage.objects.update_or_create(
                        connection=conn,
                        node=node,
                        storage=sid,
                        defaults={
                            "kind": (s.get("type") or s.get("kind") or "")[:64],
                            "status": (s.get("status") or "")[:32],
                            "total": s.get("total"),
                            "used": s.get("used"),
                            "avail": s.get("avail"),
                            "raw": s,
                        },
                    )

        existing_nets = list(ProxmoxNetwork.objects.filter(connection=conn).values_list("node", "iface"))
        for node, iface in existing_nets:
            if (node, iface) not in seen_nets:
                ProxmoxNetwork.objects.filter(connection=conn, node=node, iface=iface).delete()

        existing_stor = list(ProxmoxStorage.objects.filter(connection=conn).values_list("node", "storage"))
        for node, sid in existing_stor:
            if (node, sid) not in seen_stor:
                ProxmoxStorage.objects.filter(connection=conn, node=node, storage=sid).delete()

        conn.last_sync_at = datetime.now(tz=timezone.utc)
        conn.last_sync_ok = True
        conn.last_sync_error = ""
        conn.save(update_fields=["last_sync_at", "last_sync_ok", "last_sync_error", "updated_at"])

        return SyncResult(ok=True, nodes=len(seen_nodes), guests=len(seen_guests), networks=len(seen_nets))
    except Exception as e:
        conn.last_sync_at = datetime.now(tz=timezone.utc)
        conn.last_sync_ok = False
        conn.last_sync_error = str(e)
        conn.save(update_fields=["last_sync_at", "last_sync_ok", "last_sync_error", "updated_at"])
        return SyncResult(ok=False, nodes=0, guests=0, networks=0, error=str(e))
