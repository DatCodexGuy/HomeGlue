from __future__ import annotations

import hashlib
import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone


class Organization(models.Model):
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.name


class Location(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="locations")
    name = models.CharField(max_length=200)
    address = models.TextField(blank=True, default="")
    archived_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_core_location_org_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class Tag(models.Model):
    """
    Tags can be either:
    - global: organization is NULL
    - org-scoped: organization is set
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name="tags")
    name = models.CharField(max_length=64)

    class Meta:
        constraints = [
            # Org-scoped tags are unique per org.
            models.UniqueConstraint(fields=["organization", "name"], name="uniq_core_tag_org_name"),
            # Global tags are unique by name.
            models.UniqueConstraint(fields=["name"], condition=Q(organization__isnull=True), name="uniq_core_tag_global_name"),
        ]

    def __str__(self) -> str:
        if self.organization_id:
            return f"{self.organization}: {self.name}"
        return self.name


class FileFolder(models.Model):
    """
    Org-scoped folder for organizing files (Attachment records).

    This is intentionally simple and mirrors the Document/Password folder pattern.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="file_folders")
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
                name="uniq_core_filefolder_org_parent_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "parent", "name"], name="idx_core_filefolder_tree"),
            models.Index(fields=["organization", "archived_at"], name="idx_core_filefolder_archived"),
        ]

    def __str__(self) -> str:
        if self.parent_id:
            return f"{self.organization}: {self.parent.name} / {self.name}"
        return f"{self.organization}: {self.name}"


class Note(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="notes")
    title = models.CharField(max_length=200, blank=True, default="")
    body = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    # Optional generic link to an org-scoped object (asset, doc, password, etc).
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.CharField(max_length=64, null=True, blank=True)
    content_object = GenericForeignKey("content_type", "object_id")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.title or f"Note {self.pk}"


class Attachment(models.Model):
    """
    Generic file attachment that can be linked to any object via (content_type, object_id).
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="attachments")
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    file = models.FileField(upload_to="attachments/%Y/%m/%d/")
    filename = models.CharField(max_length=255, blank=True, default="")
    folder = models.ForeignKey(FileFolder, on_delete=models.SET_NULL, null=True, blank=True, related_name="attachments")
    tags = models.ManyToManyField(Tag, blank=True, related_name="attachments")

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.CharField(max_length=64, null=True, blank=True)
    content_object = GenericForeignKey("content_type", "object_id")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.filename and self.file:
            self.filename = getattr(self.file, "name", "") or self.filename
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Ensure underlying media file is removed as well (Django doesn't do this by default).
        storage = getattr(self.file, "storage", None)
        name = getattr(self.file, "name", None)
        super().delete(*args, **kwargs)
        try:
            if storage and name:
                storage.delete(name)
        except Exception:
            # Best-effort cleanup; ignore storage failures.
            pass

    def __str__(self) -> str:
        return self.filename or f"Attachment {self.pk}"


class AttachmentVersion(models.Model):
    """
    Historic versions of an Attachment.

    The Attachment record is considered the "current" version; older versions are stored here.
    """

    attachment = models.ForeignKey(Attachment, on_delete=models.CASCADE, related_name="versions")
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    file = models.FileField(upload_to="attachments/%Y/%m/%d/")
    filename = models.CharField(max_length=255, blank=True, default="")
    bytes = models.BigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["attachment", "-created_at"], name="idx_core_attver_recent"),
        ]

    def save(self, *args, **kwargs):
        if not self.filename and self.file:
            self.filename = getattr(self.file, "name", "") or self.filename
        if self.bytes is None and self.file:
            try:
                self.bytes = int(self.file.size)
            except Exception:
                self.bytes = None
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        storage = getattr(self.file, "storage", None)
        name = getattr(self.file, "name", None)
        super().delete(*args, **kwargs)
        try:
            if storage and name:
                storage.delete(name)
        except Exception:
            pass

    def __str__(self) -> str:
        return self.filename or f"AttachmentVersion {self.pk}"


class AttachmentShareLink(models.Model):
    """
    Public, token-based share link for an Attachment.

    - Token is only shown once at create time; DB stores SHA256 hash.
    - One-time links are consumed on first successful download.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="attachment_share_links")
    attachment = models.ForeignKey(Attachment, on_delete=models.CASCADE, related_name="share_links")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_attachment_share_links",
    )

    label = models.CharField(max_length=200, blank=True, default="")
    token_hash = models.CharField(max_length=64, unique=True)
    token_prefix = models.CharField(max_length=12, blank=True, default="")

    expires_at = models.DateTimeField()
    one_time = models.BooleanField(default=False)
    max_downloads = models.PositiveIntegerField(null=True, blank=True)
    passphrase_hash = models.CharField(max_length=255, blank=True, default="")

    consumed_at = models.DateTimeField(null=True, blank=True)
    view_count = models.IntegerField(default=0)
    last_viewed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "-created_at"], name="idx_core_attshare_org_recent"),
            models.Index(fields=["attachment", "-created_at"], name="idx_core_attshare_att_recent"),
            models.Index(fields=["expires_at"], name="idx_core_attshare_exp"),
            models.Index(fields=["revoked_at"], name="idx_core_attshare_revoked"),
            models.Index(fields=["consumed_at"], name="idx_core_attshare_consumed"),
        ]

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256((token or "").encode("utf-8")).hexdigest()

    @classmethod
    def build_new_token(cls) -> str:
        return secrets.token_urlsafe(32)

    def is_expired(self) -> bool:
        try:
            return bool(self.expires_at and self.expires_at <= timezone.now())
        except Exception:
            return True

    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def is_consumed(self) -> bool:
        if self.one_time and self.consumed_at:
            return True
        try:
            if self.max_downloads and int(self.view_count or 0) >= int(self.max_downloads):
                return True
        except Exception:
            pass
        return False

    def is_active(self) -> bool:
        return (not self.is_revoked()) and (not self.is_expired()) and (not self.is_consumed())

    def has_passphrase(self) -> bool:
        return bool((self.passphrase_hash or "").strip())

    def set_passphrase(self, passphrase: str) -> None:
        raw = (passphrase or "").strip()
        self.passphrase_hash = make_password(raw) if raw else ""

    def check_passphrase(self, passphrase: str) -> bool:
        if not self.has_passphrase():
            return True
        try:
            return check_password((passphrase or "").strip(), self.passphrase_hash)
        except Exception:
            return False

    def __str__(self) -> str:
        return f"{self.organization}: share {self.pk} for attachment {self.attachment_id}"

class CustomField(models.Model):
    """
    Custom field definitions, scoped to an organization and a model type.

    MVP: store values as strings in CustomFieldValue and interpret based on field_type.
    """

    TYPE_TEXT = "text"
    TYPE_TEXTAREA = "textarea"
    TYPE_NUMBER = "number"
    TYPE_BOOLEAN = "boolean"
    TYPE_DATE = "date"
    TYPE_URL = "url"

    TYPE_CHOICES = [
        (TYPE_TEXT, "Text"),
        (TYPE_TEXTAREA, "Long text"),
        (TYPE_NUMBER, "Number"),
        (TYPE_BOOLEAN, "Boolean"),
        (TYPE_DATE, "Date"),
        (TYPE_URL, "URL"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="custom_fields")
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="+")
    # Optional extra scoping for Flexible Assets: allow fields per flexible asset type.
    # Kept optional and generic so other models remain unaffected.
    flexible_asset_type = models.ForeignKey(
        "flexassets.FlexibleAssetType",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="custom_fields",
    )
    key = models.SlugField(max_length=64, help_text="Stable key used for API/export (e.g. 'warranty_expires').")
    name = models.CharField(max_length=120, help_text="Human-friendly label (e.g. 'Warranty Expires').")
    field_type = models.CharField(max_length=16, choices=TYPE_CHOICES, default=TYPE_TEXT)
    required = models.BooleanField(default=False)
    help_text = models.CharField(max_length=200, blank=True, default="")
    sort_order = models.IntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "content_type", "flexible_asset_type", "key"],
                name="uniq_core_customfield_org_ct_flex_key",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "content_type", "sort_order", "name"]),
            models.Index(fields=["organization", "content_type", "flexible_asset_type", "sort_order", "name"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.key}"


class CustomFieldValue(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="custom_field_values")
    field = models.ForeignKey(CustomField, on_delete=models.CASCADE, related_name="values")
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="+")
    object_id = models.CharField(max_length=64)
    value_text = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "field", "content_type", "object_id"],
                name="uniq_core_customfieldvalue_org_field_obj",
            )
        ]
        indexes = [
            models.Index(fields=["organization", "content_type", "object_id"]),
            models.Index(fields=["organization", "field"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.field.key}={self.value_text}"


class RelationshipType(models.Model):
    """
    IT Glue-style relationship types.
    Examples: "Runs On", "Backed Up By", "Connected To".
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="relationship_types")
    name = models.CharField(max_length=100)
    inverse_name = models.CharField(max_length=100, blank=True, default="")
    symmetric = models.BooleanField(
        default=False,
        help_text="If true, relationships are stored canonically (A<->B) and treated as undirected.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("organization", "name")]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class Relationship(models.Model):
    """
    Generic relationship between any two objects (source -> target).
    Stored with ContentType + object_id pairs.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="relationships")
    # CASCADE avoids orphaned relationships and allows deleting an org cleanly.
    relationship_type = models.ForeignKey(RelationshipType, on_delete=models.CASCADE, related_name="relationships")

    source_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="+")
    source_object_id = models.CharField(max_length=64)
    source_object = GenericForeignKey("source_content_type", "source_object_id")

    target_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="+")
    target_object_id = models.CharField(max_length=64)
    target_object = GenericForeignKey("target_content_type", "target_object_id")

    notes = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "relationship_type",
                    "source_content_type",
                    "source_object_id",
                    "target_content_type",
                    "target_object_id",
                ],
                name="uniq_core_relationship",
            )
        ]
        indexes = [
            models.Index(fields=["organization", "relationship_type"]),
            models.Index(fields=["organization", "source_content_type", "source_object_id"]),
            models.Index(fields=["organization", "target_content_type", "target_object_id"]),
        ]

    def _key(self, ct_id: int, obj_id: str) -> tuple[int, str]:
        return (int(ct_id), str(obj_id))

    def clean(self):
        super().clean()
        if (
            self.source_content_type_id
            and self.target_content_type_id
            and str(self.source_object_id) == str(self.target_object_id)
            and int(self.source_content_type_id) == int(self.target_content_type_id)
        ):
            raise ValidationError("Relationship cannot point to the same object.")
        if self.relationship_type_id and self.organization_id:
            if int(self.relationship_type.organization_id) != int(self.organization_id):
                raise ValidationError("Relationship type organization must match relationship organization.")

    def save(self, *args, **kwargs):
        # Canonical ordering for symmetric relationship types to avoid A<->B duplicates.
        if self.relationship_type_id and getattr(self.relationship_type, "symmetric", False):
            s_key = self._key(self.source_content_type_id, self.source_object_id)
            t_key = self._key(self.target_content_type_id, self.target_object_id)
            if s_key > t_key:
                (
                    self.source_content_type_id,
                    self.source_object_id,
                    self.target_content_type_id,
                    self.target_object_id,
                ) = (
                    self.target_content_type_id,
                    self.target_object_id,
                    self.source_content_type_id,
                    self.source_object_id,
                )
        super().save(*args, **kwargs)

    def source_label(self) -> str:
        return str(self.source_object) if self.source_object is not None else f"{self.source_content_type_id}:{self.source_object_id}"

    def target_label(self) -> str:
        return str(self.target_object) if self.target_object is not None else f"{self.target_content_type_id}:{self.target_object_id}"

    def __str__(self) -> str:
        return f"{self.organization}: {self.source_label()} -> {self.relationship_type.name} -> {self.target_label()}"


class OrganizationMembership(models.Model):
    """
    Grants a user access to an organization.

    This is the foundation for org scoping in the API (non-superusers can only
    read/write within organizations they are members of).
    """

    ROLE_OWNER = "owner"
    ROLE_ADMIN = "admin"
    ROLE_MEMBER = "member"

    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_ADMIN, "Admin"),
        (ROLE_MEMBER, "Member"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="org_memberships")
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("organization", "user")]
        indexes = [
            models.Index(fields=["user", "organization"]),
            models.Index(fields=["organization", "role"]),
        ]

    def __str__(self) -> str:
        return f"{self.user} -> {self.organization} ({self.role})"


class UserProfile(models.Model):
    """
    Small extension point for per-user preferences.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    default_organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Profile({self.user})"


class SystemSettings(models.Model):
    """
    Singleton-ish system settings that can be configured from the HomeGlue UI.

    These values are safe to store in DB (non-secret). Secrets should remain env-backed
    until we have encrypted settings storage.
    """

    # Optional base URL for building absolute links in notifications/shares.
    base_url = models.CharField(max_length=500, blank=True, default="")

    # IP access control (optional). Mirrors env vars but can be edited from UI.
    ip_allowlist = models.TextField(blank=True, default="", help_text="Comma-separated CIDRs/IPs.")
    ip_blocklist = models.TextField(blank=True, default="", help_text="Comma-separated CIDRs/IPs.")
    trust_x_forwarded_for = models.BooleanField(default=False)
    trusted_proxy_cidrs = models.TextField(blank=True, default="", help_text="Comma-separated CIDRs/IPs.")

    # Browser/API security controls (non-secret).
    # These can be applied dynamically per request (see DynamicDbSettingsMiddleware).
    cors_allowed_origins = models.TextField(blank=True, default="", help_text="Comma-separated origins (e.g. https://app.example.com).")
    csrf_trusted_origins = models.TextField(blank=True, default="", help_text="Comma-separated origins (e.g. https://homeglue.example.com).")

    # Hosts and operational tuning (non-secret).
    allowed_hosts = models.TextField(blank=True, default="", help_text="Comma-separated hosts (mirrors HOMEGLUE_ALLOWED_HOSTS).")
    reauth_ttl_seconds = models.IntegerField(default=900)
    webhook_timeout_seconds = models.IntegerField(default=8)
    smtp_timeout_seconds = models.IntegerField(default=10)

    # Email settings.
    # We support env-backed defaults, but allow a DB-backed override for convenience.
    EMAIL_SOURCE_ENV = "env"
    EMAIL_SOURCE_DB = "db"
    EMAIL_SOURCE_CHOICES = [
        (EMAIL_SOURCE_ENV, "Environment (.env)"),
        (EMAIL_SOURCE_DB, "Database (UI-configured)"),
    ]
    email_source = models.CharField(max_length=16, choices=EMAIL_SOURCE_CHOICES, default=EMAIL_SOURCE_ENV)
    email_enabled = models.BooleanField(default=False)
    email_backend = models.CharField(max_length=32, blank=True, default="console", help_text="console|smtp|smtp+tls|smtp+ssl")
    email_from = models.CharField(max_length=255, blank=True, default="")
    smtp_host = models.CharField(max_length=255, blank=True, default="")
    smtp_port = models.IntegerField(default=587)
    smtp_user = models.CharField(max_length=255, blank=True, default="")
    smtp_password_ciphertext = models.TextField(blank=True, default="")
    smtp_use_tls = models.BooleanField(default=True)
    smtp_use_ssl = models.BooleanField(default=False)

    # First-time setup wizard completion marker.
    # If unset, superusers will be redirected to the setup wizard on first login.
    setup_completed_at = models.DateTimeField(null=True, blank=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return "SystemSettings"


class WorkerHeartbeat(models.Model):
    """
    Singleton-ish heartbeat written by the `worker` container so the UI can show health.
    """

    key = models.CharField(max_length=32, unique=True, default="default")
    last_started_at = models.DateTimeField(null=True, blank=True)
    last_finished_at = models.DateTimeField(null=True, blank=True)
    last_ok = models.BooleanField(default=True)
    last_error = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"WorkerHeartbeat({self.key})"


class SavedView(models.Model):
    """
    Saved list filters per org per object type (NetBox-ish).

    MVP: store list query params in `params` (currently `q` only).
    """

    KEY_ASSET = "assets.asset"
    KEY_CONFIG_ITEM = "assets.configurationitem"
    KEY_CONTACT = "people.contact"
    KEY_LOCATION = "core.location"
    KEY_DOCUMENT = "docsapp.document"
    KEY_TEMPLATE = "docsapp.documenttemplate"
    KEY_PASSWORD = "secretsapp.passwordentry"
    KEY_DOMAIN = "netapp.domain"
    KEY_SSL_CERT = "netapp.sslcertificate"
    KEY_FILE = "core.attachment"

    KEY_CHOICES = [
        (KEY_ASSET, "Assets"),
        (KEY_CONFIG_ITEM, "Config Items"),
        (KEY_CONTACT, "Contacts"),
        (KEY_LOCATION, "Locations"),
        (KEY_DOCUMENT, "Docs"),
        (KEY_TEMPLATE, "Templates"),
        (KEY_PASSWORD, "Passwords"),
        (KEY_DOMAIN, "Domains"),
        (KEY_SSL_CERT, "SSL Certificates"),
        (KEY_FILE, "Files"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="saved_views")
    model_key = models.CharField(max_length=80, choices=KEY_CHOICES)
    name = models.CharField(max_length=120)
    params = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "model_key", "name"], name="uniq_core_savedview_org_key_name"),
        ]
        indexes = [
            models.Index(fields=["organization", "model_key", "name"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.get_model_key_display()} / {self.name}"
