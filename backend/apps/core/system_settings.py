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


def get_cors_allowed_origins_raw() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "cors_allowed_origins", "").strip():
        return str(obj.cors_allowed_origins).strip()
    return (getattr(settings, "HOMEGLUE_CORS_ALLOWED_ORIGINS", "") or "").strip()


def get_csrf_trusted_origins_raw() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "csrf_trusted_origins", "").strip():
        return str(obj.csrf_trusted_origins).strip()
    return (getattr(settings, "HOMEGLUE_CSRF_TRUSTED_ORIGINS", "") or "").strip()


def get_allowed_hosts_raw() -> str:
    obj = get_system_settings()
    if obj and getattr(obj, "allowed_hosts", "").strip():
        return str(obj.allowed_hosts).strip()
    # Fall back to env-backed value (already parsed into ALLOWED_HOSTS by Django settings module).
    try:
        hosts = list(getattr(settings, "ALLOWED_HOSTS", []) or [])
        return ",".join([str(h).strip() for h in hosts if str(h).strip()])
    except Exception:
        return ""


def get_reauth_ttl_seconds() -> int:
    obj = get_system_settings()
    if obj is not None:
        try:
            v = int(getattr(obj, "reauth_ttl_seconds", 900) or 900)
            return max(60, min(v, 86400))
        except Exception:
            return 900
    return int(getattr(settings, "HOMEGLUE_REAUTH_TTL_SECONDS", 900) or 900)


def get_webhook_timeout_seconds() -> int:
    obj = get_system_settings()
    if obj is not None:
        try:
            v = int(getattr(obj, "webhook_timeout_seconds", 8) or 8)
            return max(1, min(v, 120))
        except Exception:
            return 8
    return int(getattr(settings, "HOMEGLUE_WEBHOOK_TIMEOUT_SECONDS", 8) or 8)


def get_smtp_timeout_seconds() -> int:
    obj = get_system_settings()
    if obj is not None:
        try:
            v = int(getattr(obj, "smtp_timeout_seconds", 10) or 10)
            return max(1, min(v, 120))
        except Exception:
            return 10
    return int(getattr(settings, "HOMEGLUE_SMTP_TIMEOUT_SECONDS", 10) or 10)


def get_email_settings() -> dict[str, object]:
    """
    Return effective email settings.

    - Prefers DB-backed settings when system settings select "db".
    - Falls back to env-backed Django settings otherwise.

    Note: password is returned as plaintext when available (to configure the backend).
    """

    obj = get_system_settings()
    source = None
    try:
        source = str(getattr(obj, "email_source", "") or "").strip().lower() if obj else ""
    except Exception:
        source = ""

    if obj and source == "db":
        try:
            from apps.secretsapp.crypto import decrypt_str
        except Exception:
            decrypt_str = None

        pw = ""
        token = str(getattr(obj, "smtp_password_ciphertext", "") or "")
        if token and decrypt_str is not None:
            try:
                pw = decrypt_str(token)
            except Exception:
                pw = ""

        return {
            "source": "db",
            "enabled": bool(getattr(obj, "email_enabled", False)),
            "backend": str(getattr(obj, "email_backend", "") or "").strip().lower(),
            "from_email": str(getattr(obj, "email_from", "") or "").strip(),
            "smtp_host": str(getattr(obj, "smtp_host", "") or "").strip(),
            "smtp_port": int(getattr(obj, "smtp_port", 587) or 587),
            "smtp_user": str(getattr(obj, "smtp_user", "") or "").strip(),
            "smtp_password": pw,
            "smtp_use_tls": bool(getattr(obj, "smtp_use_tls", True)),
            "smtp_use_ssl": bool(getattr(obj, "smtp_use_ssl", False)),
        }

    # Env-backed defaults (existing behavior)
    return {
        "source": "env",
        "enabled": bool(getattr(settings, "HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED", False)),
        "backend": str(getattr(settings, "HOMEGLUE_EMAIL_BACKEND", "") or "").strip().lower(),
        "from_email": str(getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip(),
        "smtp_host": str(getattr(settings, "EMAIL_HOST", "") or "").strip(),
        "smtp_port": int(getattr(settings, "EMAIL_PORT", 587) or 587),
        "smtp_user": str(getattr(settings, "EMAIL_HOST_USER", "") or "").strip(),
        # Not exposing env password here; callers can just use Django's send_mail path.
        "smtp_password": "",
        "smtp_use_tls": bool(getattr(settings, "EMAIL_USE_TLS", False)),
        "smtp_use_ssl": bool(getattr(settings, "EMAIL_USE_SSL", False)),
    }
