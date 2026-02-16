from __future__ import annotations

from django.db import models

from apps.core.models import Organization, Tag


class Contact(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="contacts")
    first_name = models.CharField(max_length=120)
    last_name = models.CharField(max_length=120, blank=True, default="")
    email = models.EmailField(blank=True, default="")
    phone = models.CharField(max_length=50, blank=True, default="")
    title = models.CharField(max_length=120, blank=True, default="")
    notes = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="contacts")
    archived_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "last_name", "first_name"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        full = (self.first_name + " " + self.last_name).strip()
        return full or f"Contact {self.pk}"
