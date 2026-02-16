from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from django.conf import settings


@dataclass(frozen=True)
class ClientIpResult:
    ip: str | None
    source: str = "remote_addr"  # remote_addr|x_forwarded_for


def _parse_networks(raw: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for part in (raw or "").split(","):
        s = part.strip()
        if not s:
            continue
        try:
            # Accept plain IPs as /32 or /128.
            if "/" not in s:
                ip = ipaddress.ip_address(s)
                s = f"{ip}/{32 if ip.version == 4 else 128}"
            nets.append(ipaddress.ip_network(s, strict=False))
        except Exception:
            continue
    return nets


def _ip_in_any(ip: ipaddress._BaseAddress, nets: list[ipaddress._BaseNetwork]) -> bool:
    for n in nets:
        try:
            if ip in n:
                return True
        except Exception:
            continue
    return False


def get_client_ip(request) -> ClientIpResult:
    """
    Determine client IP for access control/audit.

    By default we do NOT trust X-Forwarded-For.
    If HOMEGLUE_TRUST_X_FORWARDED_FOR=true, we only trust it when REMOTE_ADDR is within HOMEGLUE_TRUSTED_PROXY_CIDRS.
    """

    remote_raw = (request.META.get("REMOTE_ADDR") or "").strip()
    try:
        remote_ip = ipaddress.ip_address(remote_raw)
    except Exception:
        remote_ip = None

    trust = bool(getattr(settings, "HOMEGLUE_TRUST_X_FORWARDED_FOR", False))
    if trust and remote_ip is not None:
        proxies = _parse_networks(getattr(settings, "HOMEGLUE_TRUSTED_PROXY_CIDRS", "") or "")
        if proxies and _ip_in_any(remote_ip, proxies):
            xff = (request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip()
            try:
                ipaddress.ip_address(xff)
                return ClientIpResult(ip=xff, source="x_forwarded_for")
            except Exception:
                pass

    return ClientIpResult(ip=remote_raw or None, source="remote_addr")


def is_request_ip_allowed(request) -> tuple[bool, str]:
    """
    Evaluate HOMEGLUE_IP_ALLOWLIST/HOMEGLUE_IP_BLOCKLIST against the request client IP.
    """

    res = get_client_ip(request)
    if not res.ip:
        return (False, "missing client ip")

    try:
        ip = ipaddress.ip_address(res.ip)
    except Exception:
        return (False, "invalid client ip")

    allow = _parse_networks(getattr(settings, "HOMEGLUE_IP_ALLOWLIST", "") or "")
    block = _parse_networks(getattr(settings, "HOMEGLUE_IP_BLOCKLIST", "") or "")

    if block and _ip_in_any(ip, block):
        return (False, "blocked")

    if allow:
        return (_ip_in_any(ip, allow), "allowlist")

    return (True, "default")

