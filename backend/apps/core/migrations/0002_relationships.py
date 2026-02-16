# Generated manually for HomeGlue (relationships).
from __future__ import annotations

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("contenttypes", "0002_remove_content_type_name"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="RelationshipType",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100)),
                ("inverse_name", models.CharField(blank=True, default="", max_length=100)),
                (
                    "symmetric",
                    models.BooleanField(
                        default=False,
                        help_text="If true, relationships are stored canonically (A<->B) and treated as undirected.",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="relationship_types",
                        to="core.organization",
                    ),
                ),
            ],
            options={"unique_together": {("organization", "name")}},
        ),
        migrations.CreateModel(
            name="Relationship",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_object_id", models.CharField(max_length=64)),
                ("target_object_id", models.CharField(max_length=64)),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="relationships",
                        to="core.organization",
                    ),
                ),
                (
                    "relationship_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="relationships",
                        to="core.relationshiptype",
                    ),
                ),
                (
                    "source_content_type",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="contenttypes.contenttype"),
                ),
                (
                    "target_content_type",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="contenttypes.contenttype"),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["organization", "relationship_type"], name="core_rel_org_type_idx"),
                    models.Index(fields=["organization", "source_content_type", "source_object_id"], name="core_rel_org_src_idx"),
                    models.Index(fields=["organization", "target_content_type", "target_object_id"], name="core_rel_org_tgt_idx"),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="relationship",
            constraint=models.UniqueConstraint(
                fields=[
                    "organization",
                    "relationship_type",
                    "source_content_type",
                    "source_object_id",
                    "target_content_type",
                    "target_object_id",
                ],
                name="uniq_core_relationship",
            ),
        ),
    ]
