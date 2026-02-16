from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.core.models import Organization, Tag

from .crypto import decrypt_str, encrypt_str
from .totp import TotpError, totp


class PasswordFolder(models.Model):
    """
    Org-scoped folder for organizing password entries (IT Glue-ish).
    Supports nesting via parent.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="password_folders")
    name = models.CharField(max_length=200)
    parent = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True, related_name="children")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "parent", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_secrets_pwfolder_org_parent_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "parent", "name"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        if self.parent_id:
            return f"{self.organization}: {self.parent.name} / {self.name}"
        return f"{self.organization}: {self.name}"


class PasswordEntry(models.Model):
    VIS_ORG = "org"
    VIS_ADMINS = "admins"
    VIS_PRIVATE = "private"
    VIS_SHARED = "shared"

    VIS_CHOICES = [
        (VIS_ORG, "Org (all members)"),
        (VIS_ADMINS, "Admins only"),
        (VIS_PRIVATE, "Private (creator only)"),
        (VIS_SHARED, "Shared (selected users)"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="password_entries")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_password_entries",
    )
    visibility = models.CharField(max_length=16, choices=VIS_CHOICES, default=VIS_ADMINS)
    allowed_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="shared_password_entries",
        help_text="Only used when visibility=Shared.",
    )
    folder = models.ForeignKey(
        PasswordFolder,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="password_entries",
    )
    name = models.CharField(max_length=200)
    username = models.CharField(max_length=200, blank=True, default="")
    password_ciphertext = models.TextField(blank=True, default="")
    totp_secret_ciphertext = models.TextField(blank=True, default="")
    totp_digits = models.PositiveSmallIntegerField(default=6)
    totp_period = models.PositiveSmallIntegerField(default=30)
    totp_algorithm = models.CharField(
        max_length=10,
        default="SHA1",
        choices=[("SHA1", "SHA1"), ("SHA256", "SHA256"), ("SHA512", "SHA512")],
    )
    url = models.URLField(blank=True, default="")
    notes = models.TextField(blank=True, default="")
    # Rotation tracking (MVP). If rotation_interval_days=0, rotation reminders are disabled.
    rotation_interval_days = models.IntegerField(default=0)
    last_changed_at = models.DateTimeField(null=True, blank=True)
    tags = models.ManyToManyField(Tag, blank=True, related_name="password_entries")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "folder", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_secrets_password_org_folder_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "archived_at"]),
            models.Index(fields=["organization", "visibility"]),
            models.Index(fields=["organization", "created_by"]),
            models.Index(fields=["organization", "folder"]),
        ]

    def set_password(self, plaintext: str) -> None:
        self.password_ciphertext = encrypt_str(plaintext or "")
        # Treat password updates as a rotation event.
        self.last_changed_at = timezone.now()

    def get_password(self) -> str:
        return decrypt_str(self.password_ciphertext)

    def rotation_due_on(self):
        """
        Returns a date when rotation is due, or None if rotation is disabled/unknown.
        """
        try:
            interval = int(self.rotation_interval_days or 0)
        except Exception:
            interval = 0
        if interval <= 0 or not self.last_changed_at:
            return None
        try:
            return (self.last_changed_at + timedelta(days=interval)).date()
        except Exception:
            return None

    def has_totp(self) -> bool:
        return bool(self.totp_secret_ciphertext)

    def set_totp_secret(self, secret_b32: str) -> None:
        self.totp_secret_ciphertext = encrypt_str(secret_b32 or "")

    def get_totp_secret(self) -> str:
        return decrypt_str(self.totp_secret_ciphertext)

    def clear_totp(self) -> None:
        self.totp_secret_ciphertext = ""

    def get_totp_code(self, *, now: int | None = None) -> tuple[str, int]:
        """
        Return (code, remaining_seconds_in_period).
        """

        if not self.has_totp():
            raise TotpError("TOTP is not enabled for this entry.")
        secret = self.get_totp_secret()
        return totp(
            secret_b32=secret,
            now=now,
            digits=int(self.totp_digits or 6),
            period=int(self.totp_period or 30),
            algorithm=(self.totp_algorithm or "SHA1"),
        )

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class PasswordShareLink(models.Model):
    """
    Public, token-based share link for a PasswordEntry.

    - Token is only ever shown at creation time; DB stores a SHA256 hash for lookup.
    - "One-time" links can only be revealed once (consumed_at is set atomically).
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="password_share_links")
    password_entry = models.ForeignKey(PasswordEntry, on_delete=models.CASCADE, related_name="share_links")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_password_share_links",
    )

    label = models.CharField(max_length=200, blank=True, default="")
    token_hash = models.CharField(max_length=64, unique=True)  # sha256 hex
    token_prefix = models.CharField(max_length=12, blank=True, default="")

    expires_at = models.DateTimeField()
    one_time = models.BooleanField(default=False)

    consumed_at = models.DateTimeField(null=True, blank=True)
    view_count = models.IntegerField(default=0)
    last_viewed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "-created_at"]),
            models.Index(fields=["password_entry", "-created_at"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["revoked_at"]),
            models.Index(fields=["consumed_at"]),
        ]

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256((token or "").encode("utf-8")).hexdigest()

    @classmethod
    def build_new_token(cls) -> str:
        # URL-safe; long enough to resist guessing.
        return secrets.token_urlsafe(32)

    def is_expired(self) -> bool:
        try:
            return bool(self.expires_at and self.expires_at <= timezone.now())
        except Exception:
            return True

    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def is_consumed(self) -> bool:
        return bool(self.one_time and self.consumed_at)

    def is_active(self) -> bool:
        return (not self.is_revoked()) and (not self.is_expired()) and (not self.is_consumed())

    def __str__(self) -> str:
        return f"{self.organization}: share {self.pk} for password {self.password_entry_id}"
