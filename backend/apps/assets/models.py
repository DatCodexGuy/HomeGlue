from __future__ import annotations

from django.db import models
from django.db.models import Q

from apps.core.models import Location, Organization, Tag


class Asset(models.Model):
    TYPE_SERVER = "server"
    TYPE_DESKTOP = "desktop"
    TYPE_LAPTOP = "laptop"
    TYPE_NETWORK = "network"
    TYPE_STORAGE = "storage"
    TYPE_IOT = "iot"
    TYPE_OTHER = "other"

    TYPE_CHOICES = [
        (TYPE_SERVER, "Server"),
        (TYPE_DESKTOP, "Desktop"),
        (TYPE_LAPTOP, "Laptop"),
        (TYPE_NETWORK, "Network"),
        (TYPE_STORAGE, "Storage"),
        (TYPE_IOT, "IoT"),
        (TYPE_OTHER, "Other"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="assets")
    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=32, choices=TYPE_CHOICES, default=TYPE_OTHER)
    manufacturer = models.CharField(max_length=120, blank=True, default="")
    model = models.CharField(max_length=120, blank=True, default="")
    serial_number = models.CharField(max_length=120, blank=True, default="")
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True, related_name="assets")
    notes = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="assets")
    archived_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_assets_asset_org_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "asset_type"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class ConfigurationItem(models.Model):
    TYPE_SERVER = "server"
    TYPE_SWITCH = "switch"
    TYPE_ROUTER = "router"
    TYPE_FIREWALL = "firewall"
    TYPE_VM = "vm"
    TYPE_CONTAINER = "container"
    TYPE_SERVICE = "service"
    TYPE_OTHER = "other"

    TYPE_CHOICES = [
        (TYPE_SERVER, "Server"),
        (TYPE_SWITCH, "Switch"),
        (TYPE_ROUTER, "Router"),
        (TYPE_FIREWALL, "Firewall"),
        (TYPE_VM, "Virtual Machine"),
        (TYPE_CONTAINER, "Container"),
        (TYPE_SERVICE, "Service"),
        (TYPE_OTHER, "Other"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="config_items")
    name = models.CharField(max_length=200)
    ci_type = models.CharField(max_length=32, choices=TYPE_CHOICES, default=TYPE_OTHER)
    hostname = models.CharField(max_length=200, blank=True, default="")
    primary_ip = models.GenericIPAddressField(null=True, blank=True)
    operating_system = models.CharField(max_length=200, blank=True, default="")
    notes = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="config_items")
    archived_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_assets_configitem_org_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "ci_type"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"
