from __future__ import annotations

from django.http import HttpResponseForbidden

from .net import is_request_ip_allowed


class DynamicDbSettingsMiddleware:
    """
    Apply DB-backed system settings to Django settings per request.

    This lets superusers change certain non-secret settings from the UI without
    editing `.env` and restarting containers.

    Important: place this middleware *before* any middleware that reads the
    affected settings (CORS, CSRF, etc.).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            from django.conf import settings

            from .system_settings import get_cors_allowed_origins_raw, get_csrf_trusted_origins_raw
            from .system_settings import get_allowed_hosts_raw, get_reauth_ttl_seconds, get_webhook_timeout_seconds, get_smtp_timeout_seconds

            def _split(raw: str) -> list[str]:
                return [p.strip() for p in (raw or "").split(",") if p.strip()]

            # corsheaders reads these from Django settings.
            settings.CORS_ALLOWED_ORIGINS = _split(get_cors_allowed_origins_raw())
            # Django CSRF middleware reads this from settings.
            settings.CSRF_TRUSTED_ORIGINS = _split(get_csrf_trusted_origins_raw())
            # Host validation (CommonMiddleware / HttpRequest.get_host).
            ah = _split(get_allowed_hosts_raw())
            if ah:
                settings.ALLOWED_HOSTS = ah

            # Operational knobs used throughout the app.
            settings.HOMEGLUE_REAUTH_TTL_SECONDS = int(get_reauth_ttl_seconds() or 900)
            settings.HOMEGLUE_WEBHOOK_TIMEOUT_SECONDS = int(get_webhook_timeout_seconds() or 8)
            settings.HOMEGLUE_SMTP_TIMEOUT_SECONDS = int(get_smtp_timeout_seconds() or 10)
        except Exception:
            pass
        return self.get_response(request)


class IpAccessControlMiddleware:
    """
    Enforce optional IP allow/block lists for the whole app (UI + API).

    Settings (env-backed):
    - HOMEGLUE_IP_ALLOWLIST: comma-separated CIDRs/IPs
    - HOMEGLUE_IP_BLOCKLIST: comma-separated CIDRs/IPs
    - HOMEGLUE_TRUST_X_FORWARDED_FOR: true/false
    - HOMEGLUE_TRUSTED_PROXY_CIDRS: CIDRs for proxies allowed to set X-Forwarded-For
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ok, _reason = is_request_ip_allowed(request)
        if not ok:
            return HttpResponseForbidden("Forbidden: client IP is not allowed.")
        return self.get_response(request)
