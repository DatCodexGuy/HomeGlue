from __future__ import annotations

from django.conf import settings


def homeglue_flags(request):
    return {
        "HOMEGLUE_OIDC_ENABLED": bool(getattr(settings, "HOMEGLUE_OIDC_ENABLED", False)),
    }

