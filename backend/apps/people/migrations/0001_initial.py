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
            name="Contact",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("first_name", models.CharField(max_length=120)),
                ("last_name", models.CharField(blank=True, default="", max_length=120)),
                ("email", models.EmailField(blank=True, default="", max_length=254)),
                ("phone", models.CharField(blank=True, default="", max_length=50)),
                ("title", models.CharField(blank=True, default="", max_length=120)),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="contacts", to="core.organization"
                    ),
                ),
                ("tags", models.ManyToManyField(blank=True, related_name="contacts", to="core.tag")),
            ],
            options={
                "indexes": [
                    models.Index(fields=["organization", "last_name", "first_name"], name="people_cont_org_lnf_idx")
                ]
            },
        ),
    ]
