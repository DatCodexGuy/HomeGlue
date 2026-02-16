from __future__ import annotations

from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core.models import Organization, Tag


class DocumentFolder(models.Model):
    """
    Org-scoped folder for organizing documents. Supports nesting via parent.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="document_folders")
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
                name="uniq_docs_docfolder_org_parent_name_active",
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


class DocumentTemplate(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="doc_templates")
    name = models.CharField(max_length=200)
    body = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="doc_templates")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_docs_template_org_name_active",
            ),
        ]
        indexes = [models.Index(fields=["organization", "archived_at"])]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class Document(models.Model):
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

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="documents")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_documents",
    )
    visibility = models.CharField(max_length=16, choices=VIS_CHOICES, default=VIS_ORG)
    allowed_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="shared_documents",
        help_text="Only used when visibility=Shared.",
    )
    title = models.CharField(max_length=255)
    folder = models.ForeignKey(
        DocumentFolder,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="documents",
    )
    body = models.TextField(blank=True, default="")
    template = models.ForeignKey(DocumentTemplate, on_delete=models.SET_NULL, null=True, blank=True, related_name="documents")
    tags = models.ManyToManyField(Tag, blank=True, related_name="documents")
    # "Flag" is an IT Glue-style quick marker for important docs.
    flagged_at = models.DateTimeField(null=True, blank=True)
    flagged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="flagged_documents",
    )
    archived_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "title"]),
            models.Index(fields=["organization", "archived_at"]),
            models.Index(fields=["organization", "visibility"]),
            models.Index(fields=["organization", "created_by"]),
            models.Index(fields=["organization", "flagged_at"]),
            models.Index(fields=["organization", "folder"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.title}"
