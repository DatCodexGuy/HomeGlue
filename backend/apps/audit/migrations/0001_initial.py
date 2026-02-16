# Generated manually for HomeGlue (initial schema).
from __future__ import annotations

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ts", models.DateTimeField(auto_now_add=True)),
                ("ip", models.GenericIPAddressField(blank=True, null=True)),
                (
                    "action",
                    models.CharField(
                        choices=[("create", "Create"), ("update", "Update"), ("delete", "Delete")],
                        max_length=16,
                    ),
                ),
                ("model", models.CharField(max_length=200)),
                ("object_pk", models.CharField(max_length=64)),
                ("summary", models.TextField(blank=True, default="")),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["ts"], name="audit_evt_ts_idx"),
                    models.Index(fields=["model", "object_pk"], name="audit_evt_model_pk_idx"),
                ],
            },
        ),
    ]
