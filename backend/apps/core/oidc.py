from __future__ import annotations

import re

from django.contrib.auth import get_user_model

from mozilla_django_oidc.auth import OIDCAuthenticationBackend


def _safe_username(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", s)
    s = s.strip("-._")
    return s[:150] or "user"


class HomeGlueOIDCBackend(OIDCAuthenticationBackend):
    """
    Minimal OIDC backend that:
    - matches existing users by email when available
    - creates a new user on first login
    """

    def filter_users_by_claims(self, claims):
        User = get_user_model()
        email = (claims.get("email") or "").strip().lower()
        if email:
            return User.objects.filter(email__iexact=email)
        sub = (claims.get("sub") or "").strip()
        if sub:
            # Fallback: try username match.
            return User.objects.filter(username__iexact=sub)
        return User.objects.none()

    def create_user(self, claims):
        User = get_user_model()
        email = (claims.get("email") or "").strip().lower()
        preferred = (claims.get("preferred_username") or "").strip()
        sub = (claims.get("sub") or "").strip()

        base = preferred or (email.split("@")[0] if email and "@" in email else "") or sub or "user"
        username = _safe_username(base)

        # Ensure uniqueness.
        candidate = username
        i = 1
        while User.objects.filter(username__iexact=candidate).exists():
            i += 1
            candidate = f"{username}-{i}"
        username = candidate

        u = User.objects.create_user(username=username, password=None)
        if email:
            u.email = email

        first = (claims.get("given_name") or claims.get("first_name") or "").strip()
        last = (claims.get("family_name") or claims.get("last_name") or "").strip()
        if hasattr(u, "first_name") and first:
            u.first_name = first
        if hasattr(u, "last_name") and last:
            u.last_name = last
        u.save()
        return u

    def update_user(self, user, claims):
        email = (claims.get("email") or "").strip().lower()
        if email and getattr(user, "email", "") != email:
            user.email = email

        first = (claims.get("given_name") or claims.get("first_name") or "").strip()
        last = (claims.get("family_name") or claims.get("last_name") or "").strip()
        if hasattr(user, "first_name") and first:
            user.first_name = first
        if hasattr(user, "last_name") and last:
            user.last_name = last
        user.save()
        return user

