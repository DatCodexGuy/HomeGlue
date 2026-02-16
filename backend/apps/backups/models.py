from __future__ import annotations

from django.conf import settings
from django.db import models

from apps.core.models import Organization


class BackupSnapshot(models.Model):
    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="backups")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_backups")

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    filename = models.CharField(max_length=255, blank=True, default="")
    file = models.FileField(upload_to="backups/%Y/%m/%d/", blank=True, null=True)
    bytes = models.BigIntegerField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "status", "-created_at"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: backup {self.pk} {self.status}"

    def delete(self, *args, **kwargs):
        # Ensure underlying media file is removed as well (Django doesn't do this by default).
        storage = getattr(self.file, "storage", None)
        name = getattr(self.file, "name", None)
        super().delete(*args, **kwargs)
        try:
            if storage and name:
                storage.delete(name)
        except Exception:
            pass


class BackupPolicy(models.Model):
    """
    Simple per-org automated backup policy.

    v1: interval-based scheduling (hours) with retention-by-count.
    """

    organization = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name="backup_policy")
    enabled = models.BooleanField(default=False)
    interval_hours = models.IntegerField(default=24, help_text="How often to schedule snapshots when enabled.")
    retention_count = models.IntegerField(default=30, help_text="How many successful snapshots to keep.")

    last_scheduled_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["enabled", "next_run_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: backups enabled={self.enabled}"


class BackupRestoreBundle(models.Model):
    """
    Uploaded backup zip bundle for guided restore.

    This is intentionally "guided" rather than automated:
    - We validate structure and show the manifest/fixture in UI.
    - We can safely extract `media/` files into MEDIA_ROOT.
    - Full DB restore still requires a deliberate operator action (fresh stack recommended).
    """

    STATUS_UPLOADED = "uploaded"
    STATUS_VALID = "valid"
    STATUS_INVALID = "invalid"

    STATUS_CHOICES = [
        (STATUS_UPLOADED, "Uploaded"),
        (STATUS_VALID, "Valid"),
        (STATUS_INVALID, "Invalid"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="backup_restore_bundles")
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="uploaded_backup_restore_bundles",
    )

    filename = models.CharField(max_length=255, blank=True, default="")
    file = models.FileField(upload_to="backups/restore/%Y/%m/%d/")
    bytes = models.BigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True, default="")

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_UPLOADED)
    manifest = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")

    validated_at = models.DateTimeField(null=True, blank=True)
    media_extracted_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "status", "-created_at"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: restore bundle {self.pk} {self.status}"
