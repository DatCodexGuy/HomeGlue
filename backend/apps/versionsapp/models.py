from __future__ import annotations

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import models

from apps.core.models import Organization


class ObjectVersion(models.Model):
    ACTION_CREATE = "create"
    ACTION_UPDATE = "update"
    ACTION_DELETE = "delete"
    ACTION_RESTORE = "restore"

    ACTION_CHOICES = [
        (ACTION_CREATE, "Create"),
        (ACTION_UPDATE, "Update"),
        (ACTION_DELETE, "Delete"),
        (ACTION_RESTORE, "Restore"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="object_versions")
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="+")
    object_id = models.CharField(max_length=64)

    action = models.CharField(max_length=16, choices=ACTION_CHOICES)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    summary = models.CharField(max_length=255, blank=True, default="")
    snapshot = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "content_type", "object_id", "-created_at"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.content_type.app_label}.{self.content_type.model}:{self.object_id} {self.action}"

