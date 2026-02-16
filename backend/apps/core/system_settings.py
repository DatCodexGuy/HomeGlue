from __future__ import annotations

import time

from django.conf import settings


_CACHE = {"ts": 0.0, "obj": None}
_TTL_SECONDS = 5.0


def _load_settings_obj():
    # Import lazily to avoid app-loading issues during migrations/startup.
    try:
        from django.db.utils import OperationalError, ProgrammingError
        from .models import SystemSettings

        return SystemSettings.objects.first()
    except Exception:
        # DB not ready / migrations not applied / etc.
        return None


def get_system_settings():
    now = time.time()
    if _CACHE["obj"] is not None and (now - float(_CACHE["ts"] or 0.0)) < _TTL_SECONDS:
        return _CACHE["obj"]
    obj = _load_settings_obj()
    _CACHE["obj"] = obj
    _CACHE["ts"] = now
    return obj


def get_base_url() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "base_url", "").strip():
        return str(obj.base_url).strip().rstrip("/")
    return (getattr(settings, "HOMEGLUE_BASE_URL", "") or "").strip().rstrip("/")


def get_ip_allowlist_raw() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "ip_allowlist", "").strip():
        return str(obj.ip_allowlist).strip()
    return (getattr(settings, "HOMEGLUE_IP_ALLOWLIST", "") or "").strip()


def get_ip_blocklist_raw() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "ip_blocklist", "").strip():
        return str(obj.ip_blocklist).strip()
    return (getattr(settings, "HOMEGLUE_IP_BLOCKLIST", "") or "").strip()


def get_trust_x_forwarded_for() -> bool:
    obj = get_system_settings()
    if obj is not None:
        return bool(getattr(obj, "trust_x_forwarded_for", False))
    return bool(getattr(settings, "HOMEGLUE_TRUST_X_FORWARDED_FOR", False))


def get_trusted_proxy_cidrs_raw() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "trusted_proxy_cidrs", "").strip():
        return str(obj.trusted_proxy_cidrs).strip()
    return (getattr(settings, "HOMEGLUE_TRUSTED_PROXY_CIDRS", "") or "").strip()

