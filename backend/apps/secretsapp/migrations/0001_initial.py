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
            name="PasswordEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                ("username", models.CharField(blank=True, default="", max_length=200)),
                ("password_ciphertext", models.TextField(blank=True, default="")),
                ("url", models.URLField(blank=True, default="")),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="password_entries",
                        to="core.organization",
                    ),
                ),
                ("tags", models.ManyToManyField(blank=True, related_name="password_entries", to="core.tag")),
            ],
            options={
                "unique_together": {("organization", "name")},
                "indexes": [models.Index(fields=["organization", "name"], name="secrets_pw_org_name_idx")],
            },
        ),
    ]
