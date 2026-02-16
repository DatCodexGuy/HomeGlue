from __future__ import annotations

from django.http import HttpResponseForbidden

from .net import is_request_ip_allowed


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

