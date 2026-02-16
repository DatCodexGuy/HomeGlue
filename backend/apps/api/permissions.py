from __future__ import annotations

from rest_framework.permissions import BasePermission


class IsSuperuserOrReadWrite(BasePermission):
    """
    Placeholder for future RBAC expansion.
    For now, require authentication; scoping is enforced in viewsets.
    """

    def has_permission(self, request, view) -> bool:
        return bool(request.user and request.user.is_authenticated)

