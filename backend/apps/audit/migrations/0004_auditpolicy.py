from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0017_attachmentsharelink_hardening"),
        ("audit", "0003_alter_auditevent_organization"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditPolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("enabled", models.BooleanField(default=True)),
                ("retention_days", models.PositiveIntegerField(default=365)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "organization",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="audit_policy",
                        to="core.organization",
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["enabled", "retention_days"], name="audit_audit_enabled_ba76a1_idx"),
                ],
            },
        ),
    ]
