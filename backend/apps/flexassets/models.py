from __future__ import annotations

from django.db import models
from django.db.models import Q

from apps.core.models import Organization, Tag


class FlexibleAssetType(models.Model):
    """
    IT Glue-style "Flexible Asset" type definition (org-scoped).
    Fields for this type are defined via CustomField (content_type=FlexibleAsset, flexible_asset_type=this type).
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="flexible_asset_types")
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True, default="")
    icon = models.CharField(max_length=64, blank=True, default="", help_text="Optional icon name (UI).")
    color = models.CharField(max_length=32, blank=True, default="", help_text="Optional color token (UI).")
    sort_order = models.IntegerField(default=100)
    archived = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("organization", "name")]
        indexes = [models.Index(fields=["organization", "archived", "sort_order", "name"])]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class FlexibleAsset(models.Model):
    """
    Flexible asset instance (org-scoped).

    Notes/Attachments/Relationships are handled generically at the core layer.
    Custom fields are scoped via CustomField.flexible_asset_type.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="flexible_assets")
    asset_type = models.ForeignKey(FlexibleAssetType, on_delete=models.CASCADE, related_name="assets")
    name = models.CharField(max_length=200)
    notes = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="flexible_assets")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "asset_type", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_flexassets_asset_org_type_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "asset_type", "name"]),
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.asset_type.name}: {self.name}"
