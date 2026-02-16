from __future__ import annotations

from django.db import models
from django.db.models import Q

from apps.core.models import Organization, Tag


class Domain(models.Model):
    """
    Org-scoped domain record (IT Glue-ish).
    Keep fields pragmatic; use custom fields for the long tail.
    """

    STATUS_ACTIVE = "active"
    STATUS_PENDING = "pending"
    STATUS_EXPIRED = "expired"
    STATUS_OTHER = "other"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_PENDING, "Pending"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_OTHER, "Other"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="domains")
    name = models.CharField(max_length=253, help_text="Domain name, e.g. example.com")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    registrar = models.CharField(max_length=200, blank=True, default="")
    dns_provider = models.CharField(max_length=200, blank=True, default="")
    expires_on = models.DateField(null=True, blank=True)
    auto_renew = models.BooleanField(default=False)
    notes = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="domains")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_netapp_domain_org_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "expires_on"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class SSLCertificate(models.Model):
    """
    Org-scoped SSL certificate record.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="ssl_certificates")
    common_name = models.CharField(max_length=253, blank=True, default="")
    subject_alt_names = models.TextField(blank=True, default="", help_text="Comma-separated SANs (optional).")
    issuer = models.CharField(max_length=255, blank=True, default="")
    serial_number = models.CharField(max_length=128, blank=True, default="")
    fingerprint_sha256 = models.CharField(max_length=128, blank=True, default="")
    not_before = models.DateField(null=True, blank=True)
    not_after = models.DateField(null=True, blank=True)
    domains = models.ManyToManyField(Domain, blank=True, related_name="ssl_certificates")
    notes = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="ssl_certificates")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "common_name"]),
            models.Index(fields=["organization", "not_after"]),
            models.Index(fields=["organization", "fingerprint_sha256"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        label = self.common_name or "SSL Certificate"
        return f"{self.organization}: {label}"
