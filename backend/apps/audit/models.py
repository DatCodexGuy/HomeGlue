from __future__ import annotations

from django.conf import settings
from django.db import models

from apps.core.models import Organization


class AuditEvent(models.Model):
    ACTION_CREATE = "create"
    ACTION_UPDATE = "update"
    ACTION_DELETE = "delete"

    ACTION_CHOICES = [
        (ACTION_CREATE, "Create"),
        (ACTION_UPDATE, "Update"),
        (ACTION_DELETE, "Delete"),
    ]

    ts = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    # Audit logs should outlive deleted orgs; don't enforce a DB-level FK constraint.
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
        db_constraint=False,
    )
    action = models.CharField(max_length=16, choices=ACTION_CHOICES)
    model = models.CharField(max_length=200)
    object_pk = models.CharField(max_length=64)
    summary = models.TextField(blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["ts"]),
            models.Index(fields=["organization", "ts"]),
            models.Index(fields=["model", "object_pk"]),
        ]

    def __str__(self) -> str:
        return f"{self.ts} {self.action} {self.model}:{self.object_pk}"
