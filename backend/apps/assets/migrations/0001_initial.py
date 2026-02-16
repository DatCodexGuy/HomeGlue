# Generated manually for HomeGlue (initial schema).
from __future__ import annotations

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Asset",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                (
                    "asset_type",
                    models.CharField(
                        choices=[
                            ("server", "Server"),
                            ("desktop", "Desktop"),
                            ("laptop", "Laptop"),
                            ("network", "Network"),
                            ("storage", "Storage"),
                            ("iot", "IoT"),
                            ("other", "Other"),
                        ],
                        default="other",
                        max_length=32,
                    ),
                ),
                ("manufacturer", models.CharField(blank=True, default="", max_length=120)),
                ("model", models.CharField(blank=True, default="", max_length=120)),
                ("serial_number", models.CharField(blank=True, default="", max_length=120)),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "location",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="assets",
                        to="core.location",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="assets", to="core.organization"
                    ),
                ),
                ("tags", models.ManyToManyField(blank=True, related_name="assets", to="core.tag")),
            ],
            options={
                "unique_together": {("organization", "name")},
                "indexes": [
                    models.Index(fields=["organization", "name"], name="assets_asset_org_name_idx"),
                    models.Index(fields=["organization", "asset_type"], name="assets_asset_org_type_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="ConfigurationItem",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                (
                    "ci_type",
                    models.CharField(
                        choices=[
                            ("server", "Server"),
                            ("switch", "Switch"),
                            ("router", "Router"),
                            ("firewall", "Firewall"),
                            ("vm", "Virtual Machine"),
                            ("container", "Container"),
                            ("service", "Service"),
                            ("other", "Other"),
                        ],
                        default="other",
                        max_length=32,
                    ),
                ),
                ("hostname", models.CharField(blank=True, default="", max_length=200)),
                ("primary_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("operating_system", models.CharField(blank=True, default="", max_length=200)),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="config_items", to="core.organization"
                    ),
                ),
                ("tags", models.ManyToManyField(blank=True, related_name="config_items", to="core.tag")),
            ],
            options={
                "unique_together": {("organization", "name")},
                "indexes": [
                    models.Index(fields=["organization", "name"], name="assets_ci_org_name_idx"),
                    models.Index(fields=["organization", "ci_type"], name="assets_ci_org_type_idx"),
                ],
            },
        ),
    ]
