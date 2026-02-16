from __future__ import annotations

from dataclasses import dataclass

from django.core.exceptions import PermissionDenied

from apps.core.models import Organization, OrganizationMembership


SESSION_ORG_KEY = "homeglue_org_id"


@dataclass(frozen=True)
class OrgContext:
    organization: Organization
    is_superuser: bool


def get_allowed_org_qs(user):
    qs = Organization.objects.all().order_by("name")
    if user and getattr(user, "is_superuser", False):
        return qs
    if not user or not user.is_authenticated:
        return qs.none()
    org_ids = OrganizationMembership.objects.filter(user=user).values_list("organization_id", flat=True)
    return qs.filter(id__in=org_ids)


def set_current_org_id(request, org_id: int) -> None:
    request.session[SESSION_ORG_KEY] = int(org_id)


def clear_current_org(request) -> None:
    request.session.pop(SESSION_ORG_KEY, None)


def get_current_org_id(request) -> int | None:
    raw = request.session.get(SESSION_ORG_KEY)
    return int(raw) if raw else None


def get_current_org_context(request) -> OrgContext | None:
    """
    Return current org context from session if valid, else None.
    """

    user = request.user
    org_id = get_current_org_id(request)
    if not org_id:
        return None

    org = Organization.objects.filter(id=org_id).first()
    if not org:
        clear_current_org(request)
        return None

    if user and getattr(user, "is_superuser", False):
        return OrgContext(organization=org, is_superuser=True)

    if not user or not user.is_authenticated:
        clear_current_org(request)
        return None

    allowed = OrganizationMembership.objects.filter(user=user, organization_id=org_id).exists()
    if not allowed:
        clear_current_org(request)
        return None

    return OrgContext(organization=org, is_superuser=False)


def require_current_org(request) -> OrgContext:
    ctx = get_current_org_context(request)
    if not ctx:
        raise PermissionDenied("Select an organization first.")
    return ctx

