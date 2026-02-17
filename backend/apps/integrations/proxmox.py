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
from apps.core.models import CustomField, CustomFieldValue, Relationship, RelationshipType, Tag
from apps.flexassets.models import FlexibleAsset, FlexibleAssetType

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
        _apply_proxmox_tags_to(org=org, obj=ci, tags=list(guest.proxmox_tags or []), pool=str(guest.pool or ""))
        _apply_proxmox_custom_fields_for_guest(org=org, guest=guest, obj=ci)
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
    _apply_proxmox_tags_to(org=org, obj=ci, tags=list(guest.proxmox_tags or []), pool=str(guest.pool or ""))
    _apply_proxmox_custom_fields_for_guest(org=org, guest=guest, obj=ci)
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
        # Nodes don't expose the same tag concepts; keep only the global marker tag for now.
        _apply_proxmox_custom_fields_for_node(org=org, node=node, obj=ci)
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
    _apply_proxmox_custom_fields_for_node(org=org, node=node, obj=ci)
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
    _apply_proxmox_tags_to(org=org, obj=asset, tags=list(guest.proxmox_tags or []), pool=str(guest.pool or ""))
    _apply_proxmox_custom_fields_for_guest(org=org, guest=guest, obj=asset)

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
    _apply_proxmox_custom_fields_for_node(org=org, node=node, obj=asset)

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


def _ensure_guest_asset_hosted_on_node_asset(*, org, guest: ProxmoxGuest, node: ProxmoxNode | None) -> None:
    if not guest.asset_id or not node or not node.asset_id:
        return
    rt, _ = RelationshipType.objects.get_or_create(
        organization=org,
        name="Hosted On",
        defaults={"inverse_name": "Hosts", "symmetric": False},
    )
    a_ct = ContentType.objects.get_for_model(Asset)
    Relationship.objects.get_or_create(
        organization=org,
        relationship_type=rt,
        source_content_type=a_ct,
        source_object_id=str(guest.asset_id),
        target_content_type=a_ct,
        target_object_id=str(node.asset_id),
        defaults={"notes": f"[proxmox] {guest.connection.name}"},
    )


def _ensure_connected_to(*, org, left_obj, right_obj, note: str) -> None:
    """
    Create a symmetric "Connected To" relationship between two objects.
    """

    rt, _ = RelationshipType.objects.get_or_create(
        organization=org,
        name="Connected To",
        defaults={"inverse_name": "Connected To", "symmetric": True},
    )
    left_ct = ContentType.objects.get_for_model(left_obj.__class__)
    right_ct = ContentType.objects.get_for_model(right_obj.__class__)

    l_key = (int(left_ct.id), str(left_obj.pk))
    r_key = (int(right_ct.id), str(right_obj.pk))
    if r_key < l_key:
        left_ct, right_ct = right_ct, left_ct
        left_obj, right_obj = right_obj, left_obj

    Relationship.objects.get_or_create(
        organization=org,
        relationship_type=rt,
        source_content_type=left_ct,
        source_object_id=str(left_obj.pk),
        target_content_type=right_ct,
        target_object_id=str(right_obj.pk),
        defaults={"notes": note[:5000]},
    )


def _ensure_linked_relationship(*, org, left_obj, right_obj, note: str) -> None:
    """
    Create a symmetric "Linked To" relationship between two objects (any types).

    We canonicalize the source/target ordering up-front to avoid IntegrityError
    when a reversed relationship already exists.
    """

    rt, _ = RelationshipType.objects.get_or_create(
        organization=org,
        name="Linked To",
        defaults={"inverse_name": "Linked To", "symmetric": True},
    )
    left_ct = ContentType.objects.get_for_model(left_obj.__class__)
    right_ct = ContentType.objects.get_for_model(right_obj.__class__)

    l_key = (int(left_ct.id), str(left_obj.pk))
    r_key = (int(right_ct.id), str(right_obj.pk))
    if r_key < l_key:
        left_ct, right_ct = right_ct, left_ct
        left_obj, right_obj = right_obj, left_obj

    Relationship.objects.get_or_create(
        organization=org,
        relationship_type=rt,
        source_content_type=left_ct,
        source_object_id=str(left_obj.pk),
        target_content_type=right_ct,
        target_object_id=str(right_obj.pk),
        defaults={"notes": note[:5000]},
    )


def _apply_proxmox_tags_to(*, org, obj, tags: list[str], pool: str = "") -> None:
    """
    Translate Proxmox tags/pool into HomeGlue Tags on the target object.
    """

    if not hasattr(obj, "tags"):
        return

    names: list[str] = []
    for t in (tags or [])[:50]:
        t = (t or "").strip()
        if not t:
            continue
        names.append(f"proxmox:{t}"[:100])
    if pool:
        names.append(f"proxmox:pool:{pool}"[:100])
    if not names:
        return

    for name in names:
        tag, _ = Tag.objects.get_or_create(organization=org, name=name)
        obj.tags.add(tag)


def _get_or_create_cf(*, org, model_cls, key: str, name: str, field_type: str, sort_order: int) -> CustomField:
    """
    Upsert a Proxmox-related CustomField definition for a given model class.
    """

    ct = ContentType.objects.get_for_model(model_cls)
    cf, _ = CustomField.objects.get_or_create(
        organization=org,
        content_type=ct,
        flexible_asset_type=None,
        key=key[:64],
        defaults={
            "name": name[:120],
            "field_type": field_type,
            "required": False,
            "help_text": "Synced from Proxmox.",
            "sort_order": int(sort_order),
        },
    )
    # Keep definitions stable but allow us to improve labels/order over time.
    changed = False
    if cf.name != name[:120]:
        cf.name = name[:120]
        changed = True
    if cf.field_type != field_type:
        cf.field_type = field_type
        changed = True
    if cf.help_text != "Synced from Proxmox.":
        cf.help_text = "Synced from Proxmox."
        changed = True
    if int(cf.sort_order or 0) != int(sort_order):
        cf.sort_order = int(sort_order)
        changed = True
    if changed:
        cf.save(update_fields=["name", "field_type", "help_text", "sort_order"])
    return cf


def _set_cf_value(*, org, obj, key: str, name: str, field_type: str, sort_order: int, value) -> None:
    """
    Upsert a CustomFieldValue on obj, creating the CustomField if needed.
    """

    if value is None:
        return
    if field_type == CustomField.TYPE_BOOLEAN:
        v = "true" if bool(value) else "false"
    else:
        v = str(value).strip()
    if not v:
        return

    cf = _get_or_create_cf(org=org, model_cls=obj.__class__, key=key, name=name, field_type=field_type, sort_order=sort_order)
    ct = ContentType.objects.get_for_model(obj.__class__)
    CustomFieldValue.objects.update_or_create(
        organization=org,
        field=cf,
        content_type=ct,
        object_id=str(obj.pk),
        defaults={"value_text": v},
    )


def _apply_proxmox_custom_fields_for_guest(*, org, guest: ProxmoxGuest, obj) -> None:
    """
    Apply a consistent set of Proxmox metadata to either an Asset or ConfigItem.
    """

    base_sort = 10
    _set_cf_value(org=org, obj=obj, key="proxmox_connection", name="Proxmox Connection", field_type=CustomField.TYPE_TEXT, sort_order=base_sort, value=guest.connection.name)
    _set_cf_value(org=org, obj=obj, key="proxmox_base_url", name="Proxmox Base URL", field_type=CustomField.TYPE_URL, sort_order=base_sort + 1, value=guest.connection.base_url)
    _set_cf_value(org=org, obj=obj, key="proxmox_guest_type", name="Proxmox Guest Type", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 2, value=guest.guest_type)
    _set_cf_value(org=org, obj=obj, key="proxmox_vmid", name="Proxmox VMID", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 3, value=guest.vmid)
    _set_cf_value(org=org, obj=obj, key="proxmox_node", name="Proxmox Node", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 4, value=guest.node)
    _set_cf_value(org=org, obj=obj, key="proxmox_status", name="Proxmox Status", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 5, value=guest.status)
    _set_cf_value(org=org, obj=obj, key="proxmox_uptime", name="Proxmox Uptime", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 6, value=guest.uptime)
    _set_cf_value(org=org, obj=obj, key="proxmox_maxcpu", name="Proxmox vCPU (max)", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 7, value=guest.maxcpu)
    _set_cf_value(org=org, obj=obj, key="proxmox_maxmem", name="Proxmox Memory", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 8, value=guest.maxmem)
    _set_cf_value(org=org, obj=obj, key="proxmox_maxdisk", name="Proxmox Disk", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 9, value=guest.maxdisk)
    _set_cf_value(org=org, obj=obj, key="proxmox_ostype", name="Proxmox OS Type", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 10, value=guest.ostype)
    _set_cf_value(org=org, obj=obj, key="proxmox_pool", name="Proxmox Pool", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 11, value=guest.pool)
    _set_cf_value(org=org, obj=obj, key="proxmox_agent_hostname", name="Proxmox Agent Hostname", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 12, value=guest.agent_hostname)
    if guest.ip_addrs:
        _set_cf_value(
            org=org,
            obj=obj,
            key="proxmox_ips",
            name="Proxmox IPs",
            field_type=CustomField.TYPE_TEXTAREA,
            sort_order=base_sort + 13,
            value="\n".join([str(x) for x in (guest.ip_addrs or [])[:50] if str(x).strip()]),
        )


def _apply_proxmox_custom_fields_for_node(*, org, node: ProxmoxNode, obj) -> None:
    base_sort = 10
    _set_cf_value(org=org, obj=obj, key="proxmox_connection", name="Proxmox Connection", field_type=CustomField.TYPE_TEXT, sort_order=base_sort, value=node.connection.name)
    _set_cf_value(org=org, obj=obj, key="proxmox_base_url", name="Proxmox Base URL", field_type=CustomField.TYPE_URL, sort_order=base_sort + 1, value=node.connection.base_url)
    _set_cf_value(org=org, obj=obj, key="proxmox_node", name="Proxmox Node", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 2, value=node.node)
    _set_cf_value(org=org, obj=obj, key="proxmox_status", name="Proxmox Status", field_type=CustomField.TYPE_TEXT, sort_order=base_sort + 3, value=node.status)
    _set_cf_value(org=org, obj=obj, key="proxmox_uptime", name="Proxmox Uptime", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 4, value=node.uptime)
    _set_cf_value(org=org, obj=obj, key="proxmox_maxcpu", name="Proxmox CPU (max)", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 5, value=node.maxcpu)
    _set_cf_value(org=org, obj=obj, key="proxmox_maxmem", name="Proxmox Memory", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 6, value=node.maxmem)
    _set_cf_value(org=org, obj=obj, key="proxmox_maxdisk", name="Proxmox Disk", field_type=CustomField.TYPE_NUMBER, sort_order=base_sort + 7, value=node.maxdisk)
    if isinstance(getattr(node, "version_raw", None), dict):
        _set_cf_value(
            org=org,
            obj=obj,
            key="proxmox_version",
            name="Proxmox Version",
            field_type=CustomField.TYPE_TEXT,
            sort_order=base_sort + 8,
            value=(node.version_raw or {}).get("version") or "",
        )


def _ensure_flex_type(*, org, name: str, description: str, icon: str, color: str, sort_order: int) -> FlexibleAssetType:
    ft, _ = FlexibleAssetType.objects.get_or_create(
        organization=org,
        name=name[:120],
        defaults={
            "description": description,
            "icon": icon[:64],
            "color": color[:32],
            "sort_order": int(sort_order),
            "archived": False,
        },
    )
    changed = False
    if (ft.description or "") != (description or ""):
        ft.description = description or ""
        changed = True
    if (ft.icon or "") != (icon or ""):
        ft.icon = icon[:64]
        changed = True
    if (ft.color or "") != (color or ""):
        ft.color = color[:32]
        changed = True
    if int(ft.sort_order or 0) != int(sort_order):
        ft.sort_order = int(sort_order)
        changed = True
    if bool(ft.archived):
        ft.archived = False
        changed = True
    if changed:
        ft.save(update_fields=["description", "icon", "color", "sort_order", "archived", "updated_at"])
    return ft


def _ensure_flex_asset(*, org, ftype: FlexibleAssetType, name: str, marker: str) -> FlexibleAsset:
    fa, _ = FlexibleAsset.objects.get_or_create(
        organization=org,
        asset_type=ftype,
        name=name[:200],
        defaults={"notes": marker[:5000]},
    )
    if marker and marker not in (fa.notes or ""):
        fa.notes = ((fa.notes or "").strip() + ("\n" if (fa.notes or "").strip() else "") + marker).strip()[:5000]
        fa.save(update_fields=["notes", "updated_at"])
    tag, _ = Tag.objects.get_or_create(organization=org, name="synced:proxmox")
    fa.tags.add(tag)
    return fa


def _get_or_create_flex_cf(*, org, flex_type: FlexibleAssetType, key: str, name: str, field_type: str, sort_order: int) -> CustomField:
    ct = ContentType.objects.get_for_model(FlexibleAsset)
    cf, _ = CustomField.objects.get_or_create(
        organization=org,
        content_type=ct,
        flexible_asset_type=flex_type,
        key=key[:64],
        defaults={
            "name": name[:120],
            "field_type": field_type,
            "required": False,
            "help_text": "Synced from Proxmox.",
            "sort_order": int(sort_order),
        },
    )
    changed = False
    if cf.name != name[:120]:
        cf.name = name[:120]
        changed = True
    if cf.field_type != field_type:
        cf.field_type = field_type
        changed = True
    if cf.help_text != "Synced from Proxmox.":
        cf.help_text = "Synced from Proxmox."
        changed = True
    if int(cf.sort_order or 0) != int(sort_order):
        cf.sort_order = int(sort_order)
        changed = True
    if changed:
        cf.save(update_fields=["name", "field_type", "help_text", "sort_order"])
    return cf


def _set_flex_cf_value(*, org, flex_type: FlexibleAssetType, flex_asset: FlexibleAsset, key: str, name: str, field_type: str, sort_order: int, value) -> None:
    if value is None:
        return
    v = str(value).strip()
    if not v:
        return
    cf = _get_or_create_flex_cf(org=org, flex_type=flex_type, key=key, name=name, field_type=field_type, sort_order=sort_order)
    ct = ContentType.objects.get_for_model(FlexibleAsset)
    CustomFieldValue.objects.update_or_create(
        organization=org,
        field=cf,
        content_type=ct,
        object_id=str(flex_asset.pk),
        defaults={"value_text": v},
    )


def _parse_storage_ids_from_guest_config(config: dict) -> set[str]:
    if not isinstance(config, dict):
        return set()
    storage_ids: set[str] = set()
    keys = set(config.keys())
    # QEMU disks like scsi0, sata0, virtio0, ide0, efidisk0, tpmstate0; LXC: rootfs, mp0..mp9
    for k in keys:
        ks = str(k or "").lower()
        if not (ks.startswith(("scsi", "sata", "virtio", "ide", "efidisk", "tpmstate", "mp")) or ks in {"rootfs"}):
            continue
        raw = str(config.get(k) or "")
        if ":" not in raw:
            continue
        first = raw.split(",", 1)[0].strip()
        if ":" not in first:
            continue
        sid = first.split(":", 1)[0].strip()
        if sid:
            storage_ids.add(sid[:200])
    return storage_ids


def _parse_bridges_from_guest_config(config: dict) -> set[str]:
    if not isinstance(config, dict):
        return set()
    bridges: set[str] = set()
    for k, v in (config or {}).items():
        ks = str(k or "").lower()
        if not ks.startswith("net"):
            continue
        s = str(v or "")
        for chunk in s.split(","):
            chunk = chunk.strip()
            if chunk.startswith("bridge="):
                b = chunk.split("=", 1)[1].strip()
                if b:
                    bridges.add(b[:200])
    return bridges

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

        # Flexible Assets: Proxmox primitives (org-scoped, per connection).
        org = conn.organization
        ft_cluster = _ensure_flex_type(
            org=org,
            name="Proxmox Cluster",
            description="Proxmox cluster snapshot (synced).",
            icon="shapes",
            color="sky",
            sort_order=10,
        )
        ft_pool = _ensure_flex_type(
            org=org,
            name="Proxmox Pool",
            description="Proxmox resource pools (synced).",
            icon="box",
            color="teal",
            sort_order=20,
        )
        ft_vnet = _ensure_flex_type(
            org=org,
            name="Proxmox SDN VNet",
            description="Proxmox SDN VNets (synced).",
            icon="link",
            color="indigo",
            sort_order=30,
        )
        ft_subnet = _ensure_flex_type(
            org=org,
            name="Proxmox SDN Subnet",
            description="Proxmox SDN subnets (synced).",
            icon="globe",
            color="indigo",
            sort_order=31,
        )
        ft_zone = _ensure_flex_type(
            org=org,
            name="Proxmox SDN Zone",
            description="Proxmox SDN zones (synced).",
            icon="globe",
            color="indigo",
            sort_order=32,
        )
        ft_net = _ensure_flex_type(
            org=org,
            name="Proxmox Network Interface",
            description="Proxmox node network interfaces (synced).",
            icon="wifi",
            color="blue",
            sort_order=40,
        )
        ft_storage = _ensure_flex_type(
            org=org,
            name="Proxmox Storage",
            description="Proxmox node storages (synced).",
            icon="database",
            color="slate",
            sort_order=50,
        )

        pool_flex: dict[str, FlexibleAsset] = {}
        vnet_flex: dict[str, FlexibleAsset] = {}
        subnet_flex: dict[str, FlexibleAsset] = {}
        zone_flex: dict[str, FlexibleAsset] = {}

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
                fa = _ensure_flex_asset(org=org, ftype=ft_pool, name=pid, marker=f"[proxmox] {conn.name} pool={pid}")
                _set_flex_cf_value(org=org, flex_type=ft_pool, flex_asset=fa, key="poolid", name="Pool ID", field_type=CustomField.TYPE_TEXT, sort_order=10, value=pid)
                _set_flex_cf_value(org=org, flex_type=ft_pool, flex_asset=fa, key="comment", name="Comment", field_type=CustomField.TYPE_TEXTAREA, sort_order=20, value=(p.get("comment") or p.get("remark") or ""))
                _set_flex_cf_value(org=org, flex_type=ft_pool, flex_asset=fa, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=30, value=conn.name)
                _set_flex_cf_value(org=org, flex_type=ft_pool, flex_asset=fa, key="base_url", name="Base URL", field_type=CustomField.TYPE_URL, sort_order=31, value=conn.base_url)
                pool_flex[pid] = fa
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
                fa = _ensure_flex_asset(org=org, ftype=ft_zone, name=zid, marker=f"[proxmox] {conn.name} zone={zid}")
                _set_flex_cf_value(org=org, flex_type=ft_zone, flex_asset=fa, key="zone", name="Zone", field_type=CustomField.TYPE_TEXT, sort_order=10, value=zid)
                _set_flex_cf_value(org=org, flex_type=ft_zone, flex_asset=fa, key="kind", name="Kind", field_type=CustomField.TYPE_TEXT, sort_order=20, value=(z.get("type") or z.get("kind") or ""))
                _set_flex_cf_value(org=org, flex_type=ft_zone, flex_asset=fa, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=30, value=conn.name)
                zone_flex[zid] = fa
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
                fa = _ensure_flex_asset(org=org, ftype=ft_vnet, name=vid, marker=f"[proxmox] {conn.name} vnet={vid}")
                _set_flex_cf_value(org=org, flex_type=ft_vnet, flex_asset=fa, key="vnet", name="VNet", field_type=CustomField.TYPE_TEXT, sort_order=10, value=vid)
                _set_flex_cf_value(org=org, flex_type=ft_vnet, flex_asset=fa, key="zone", name="Zone", field_type=CustomField.TYPE_TEXT, sort_order=20, value=v.get("zone") or "")
                _set_flex_cf_value(org=org, flex_type=ft_vnet, flex_asset=fa, key="alias", name="Alias", field_type=CustomField.TYPE_TEXT, sort_order=30, value=(v.get("alias") or v.get("comment") or ""))
                _set_flex_cf_value(org=org, flex_type=ft_vnet, flex_asset=fa, key="tag", name="Tag", field_type=CustomField.TYPE_NUMBER, sort_order=40, value=tag)
                _set_flex_cf_value(org=org, flex_type=ft_vnet, flex_asset=fa, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=50, value=conn.name)
                vnet_flex[vid] = fa
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
                fa = _ensure_flex_asset(org=org, ftype=ft_subnet, name=sid, marker=f"[proxmox] {conn.name} subnet={sid}")
                _set_flex_cf_value(org=org, flex_type=ft_subnet, flex_asset=fa, key="subnet", name="Subnet", field_type=CustomField.TYPE_TEXT, sort_order=10, value=sid)
                _set_flex_cf_value(org=org, flex_type=ft_subnet, flex_asset=fa, key="vnet", name="VNet", field_type=CustomField.TYPE_TEXT, sort_order=20, value=s.get("vnet") or "")
                _set_flex_cf_value(org=org, flex_type=ft_subnet, flex_asset=fa, key="gateway", name="Gateway", field_type=CustomField.TYPE_TEXT, sort_order=30, value=s.get("gateway") or "")
                subnet_flex[sid] = fa
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
            if node_obj.asset_id and node_obj.config_item_id:
                _ensure_linked_relationship(
                    org=conn.organization,
                    left_obj=node_obj.asset,
                    right_obj=node_obj.config_item,
                    note=f"[proxmox] {conn.name} node={node_obj.node}",
                )
            node_obj_by_name[node] = node_obj
        ProxmoxNode.objects.filter(connection=conn).exclude(node__in=list(seen_nodes)).delete()

        # Cluster flexible asset and node membership relationships.
        cluster_name = ""
        cluster_ver = ""
        if isinstance(cluster, list):
            for row in cluster:
                if isinstance(row, dict) and row.get("type") == "cluster":
                    cluster_name = str(row.get("name") or "").strip()
                    cluster_ver = str(row.get("version") or "").strip()
                    break
        if not cluster_name:
            cluster_name = conn.name or "Proxmox"
        fa_cluster = _ensure_flex_asset(org=org, ftype=ft_cluster, name=cluster_name, marker=f"[proxmox] {conn.name} cluster={cluster_name}")
        _set_flex_cf_value(org=org, flex_type=ft_cluster, flex_asset=fa_cluster, key="cluster_name", name="Cluster Name", field_type=CustomField.TYPE_TEXT, sort_order=10, value=cluster_name)
        _set_flex_cf_value(org=org, flex_type=ft_cluster, flex_asset=fa_cluster, key="cluster_version", name="Cluster Version", field_type=CustomField.TYPE_TEXT, sort_order=20, value=cluster_ver)
        _set_flex_cf_value(org=org, flex_type=ft_cluster, flex_asset=fa_cluster, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=30, value=conn.name)
        _set_flex_cf_value(org=org, flex_type=ft_cluster, flex_asset=fa_cluster, key="base_url", name="Base URL", field_type=CustomField.TYPE_URL, sort_order=31, value=conn.base_url)

        rt_member, _ = RelationshipType.objects.get_or_create(
            organization=org,
            name="Member Of",
            defaults={"inverse_name": "Has Member", "symmetric": False},
        )
        for node_name, node_obj in node_obj_by_name.items():
            for obj in [node_obj.asset, node_obj.config_item]:
                if not obj:
                    continue
                ct_obj = ContentType.objects.get_for_model(obj.__class__)
                ct_fa = ContentType.objects.get_for_model(FlexibleAsset)
                Relationship.objects.get_or_create(
                    organization=org,
                    relationship_type=rt_member,
                    source_content_type=ct_obj,
                    source_object_id=str(obj.pk),
                    target_content_type=ct_fa,
                    target_object_id=str(fa_cluster.pk),
                    defaults={"notes": f"[proxmox] {conn.name} node={node_name}"},
                )

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
                # Link the created HomeGlue objects for easy navigation.
                if guest_obj.asset_id and guest_obj.config_item_id:
                    _ensure_linked_relationship(
                        org=conn.organization,
                        left_obj=guest_obj.asset,
                        right_obj=guest_obj.config_item,
                        note=f"[proxmox] {conn.name} {guest_obj.guest_type}:{guest_obj.vmid}",
                    )
                host_node = node_obj_by_name.get(node) if node else None
                if not host_node and node:
                    host_node = ProxmoxNode.objects.filter(connection=conn, node=node).select_related("config_item").first()
                _ensure_hosted_on_relationship(org=conn.organization, guest=guest_obj, node=host_node)
                _ensure_guest_asset_hosted_on_node_asset(org=conn.organization, guest=guest_obj, node=host_node)

                # Guest -> network/storage relationships (best-effort from config).
                cfg = guest_obj.config_raw or {}
                bridges = _parse_bridges_from_guest_config(cfg if isinstance(cfg, dict) else {})
                storage_ids = _parse_storage_ids_from_guest_config(cfg if isinstance(cfg, dict) else {})
                ct_fa = ContentType.objects.get_for_model(FlexibleAsset)

                # Connected To (guest <-> interface)
                for br in sorted(list(bridges))[:20]:
                    if not guest_obj.node:
                        continue
                    fa_net = _ensure_flex_asset(org=org, ftype=ft_net, name=f"{guest_obj.node}:{br}", marker=f"[proxmox] {conn.name} net={guest_obj.node}:{br}")
                    _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="node", name="Node", field_type=CustomField.TYPE_TEXT, sort_order=10, value=guest_obj.node)
                    _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="iface", name="Interface", field_type=CustomField.TYPE_TEXT, sort_order=20, value=br)
                    _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=60, value=conn.name)
                    for obj in [guest_obj.asset, guest_obj.config_item]:
                        if not obj:
                            continue
                        _ensure_connected_to(org=org, left_obj=obj, right_obj=fa_net, note=f"[proxmox] {conn.name}")

                # Uses Storage (guest -> storage)
                rt_storage, _ = RelationshipType.objects.get_or_create(
                    organization=org,
                    name="Uses Storage",
                    defaults={"inverse_name": "Used By", "symmetric": False},
                )
                for sid in sorted(list(storage_ids))[:20]:
                    if not guest_obj.node:
                        continue
                    fa_st = _ensure_flex_asset(org=org, ftype=ft_storage, name=f"{guest_obj.node}:{sid}", marker=f"[proxmox] {conn.name} storage={guest_obj.node}:{sid}")
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="node", name="Node", field_type=CustomField.TYPE_TEXT, sort_order=10, value=guest_obj.node)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="storage", name="Storage", field_type=CustomField.TYPE_TEXT, sort_order=20, value=sid)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=60, value=conn.name)
                    for obj in [guest_obj.asset, guest_obj.config_item]:
                        if not obj:
                            continue
                        ct_obj = ContentType.objects.get_for_model(obj.__class__)
                        Relationship.objects.get_or_create(
                            organization=org,
                            relationship_type=rt_storage,
                            source_content_type=ct_obj,
                            source_object_id=str(obj.pk),
                            target_content_type=ct_fa,
                            target_object_id=str(fa_st.pk),
                            defaults={"notes": f"[proxmox] {conn.name}"},
                        )

                # Guest -> Pool relationship (if any)
                if guest_obj.pool:
                    pid = str(guest_obj.pool).strip()
                    if pid:
                        fa_pool = pool_flex.get(pid) or _ensure_flex_asset(org=org, ftype=ft_pool, name=pid, marker=f"[proxmox] {conn.name} pool={pid}")
                        pool_flex[pid] = fa_pool
                        rt_in_pool, _ = RelationshipType.objects.get_or_create(
                            organization=org,
                            name="In Pool",
                            defaults={"inverse_name": "Contains", "symmetric": False},
                        )
                        ct_fa = ContentType.objects.get_for_model(FlexibleAsset)
                        for obj in [guest_obj.asset, guest_obj.config_item]:
                            if not obj:
                                continue
                            ct_obj = ContentType.objects.get_for_model(obj.__class__)
                            Relationship.objects.get_or_create(
                                organization=org,
                                relationship_type=rt_in_pool,
                                source_content_type=ct_obj,
                                source_object_id=str(obj.pk),
                                target_content_type=ct_fa,
                                target_object_id=str(fa_pool.pk),
                                defaults={"notes": f"[proxmox] {conn.name}"},
                            )

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
                net_obj, _ = ProxmoxNetwork.objects.update_or_create(
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
                fa_net = _ensure_flex_asset(org=org, ftype=ft_net, name=f"{node}:{iface}", marker=f"[proxmox] {conn.name} net={node}:{iface}")
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="node", name="Node", field_type=CustomField.TYPE_TEXT, sort_order=10, value=node)
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="iface", name="Interface", field_type=CustomField.TYPE_TEXT, sort_order=20, value=iface)
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="kind", name="Kind", field_type=CustomField.TYPE_TEXT, sort_order=30, value=net_obj.kind)
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="address", name="Address", field_type=CustomField.TYPE_TEXT, sort_order=40, value=net_obj.address)
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="netmask", name="Netmask", field_type=CustomField.TYPE_TEXT, sort_order=41, value=net_obj.netmask)
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="gateway", name="Gateway", field_type=CustomField.TYPE_TEXT, sort_order=42, value=net_obj.gateway)
                _set_flex_cf_value(org=org, flex_type=ft_net, flex_asset=fa_net, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=60, value=conn.name)

                # Node has interface relationship.
                rt_iface, _ = RelationshipType.objects.get_or_create(
                    organization=org,
                    name="Has Interface",
                    defaults={"inverse_name": "Interface Of", "symmetric": False},
                )
                ct_fa = ContentType.objects.get_for_model(FlexibleAsset)
                node_obj = node_obj_by_name.get(node)
                if node_obj:
                    for obj in [node_obj.asset, node_obj.config_item]:
                        if not obj:
                            continue
                        ct_obj = ContentType.objects.get_for_model(obj.__class__)
                        Relationship.objects.get_or_create(
                            organization=org,
                            relationship_type=rt_iface,
                            source_content_type=ct_obj,
                            source_object_id=str(obj.pk),
                            target_content_type=ct_fa,
                            target_object_id=str(fa_net.pk),
                            defaults={"notes": f"[proxmox] {conn.name}"},
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
                    stor_obj, _ = ProxmoxStorage.objects.update_or_create(
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
                    fa_st = _ensure_flex_asset(org=org, ftype=ft_storage, name=f"{node}:{sid}", marker=f"[proxmox] {conn.name} storage={node}:{sid}")
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="node", name="Node", field_type=CustomField.TYPE_TEXT, sort_order=10, value=node)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="storage", name="Storage", field_type=CustomField.TYPE_TEXT, sort_order=20, value=sid)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="kind", name="Kind", field_type=CustomField.TYPE_TEXT, sort_order=30, value=stor_obj.kind)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="status", name="Status", field_type=CustomField.TYPE_TEXT, sort_order=31, value=stor_obj.status)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="total", name="Total", field_type=CustomField.TYPE_NUMBER, sort_order=40, value=stor_obj.total)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="used", name="Used", field_type=CustomField.TYPE_NUMBER, sort_order=41, value=stor_obj.used)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="avail", name="Available", field_type=CustomField.TYPE_NUMBER, sort_order=42, value=stor_obj.avail)
                    _set_flex_cf_value(org=org, flex_type=ft_storage, flex_asset=fa_st, key="connection", name="Connection", field_type=CustomField.TYPE_TEXT, sort_order=60, value=conn.name)

                    rt_storage, _ = RelationshipType.objects.get_or_create(
                        organization=org,
                        name="Uses Storage",
                        defaults={"inverse_name": "Used By", "symmetric": False},
                    )
                    ct_fa = ContentType.objects.get_for_model(FlexibleAsset)
                    node_obj = node_obj_by_name.get(node)
                    if node_obj:
                        for obj in [node_obj.asset, node_obj.config_item]:
                            if not obj:
                                continue
                            ct_obj = ContentType.objects.get_for_model(obj.__class__)
                            Relationship.objects.get_or_create(
                                organization=org,
                                relationship_type=rt_storage,
                                source_content_type=ct_obj,
                                source_object_id=str(obj.pk),
                                target_content_type=ct_fa,
                                target_object_id=str(fa_st.pk),
                                defaults={"notes": f"[proxmox] {conn.name}"},
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
