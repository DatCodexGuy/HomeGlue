from __future__ import annotations

from django.shortcuts import redirect
from django.urls import reverse
from urllib.parse import urlencode

from .org import get_current_org_context


class OrgRequiredMiddleware:
    """
    UI-only guardrail: if a user is authenticated but has not "entered" an org yet,
    redirect them to the org picker instead of raising a 403 deep in the view layer.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not request.path.startswith("/app/"):
            return None

        if not request.user.is_authenticated:
            return None

        match = getattr(request, "resolver_match", None)
        if match and (
            match.view_name in {"ui:home", "ui:enter_org", "ui:leave_org", "ui:reauth", "ui:account"}
            or str(match.view_name or "").startswith("ui:super_admin_")
        ):
            return None

        # If we don't have a valid org context yet, force the org picker.
        if not get_current_org_context(request):
            next_url = request.get_full_path()
            return redirect(f"{reverse('ui:home')}?{urlencode({'next': next_url})}")

        return None
