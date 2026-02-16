from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0014_attachment_versions"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AttachmentShareLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("label", models.CharField(blank=True, default="", max_length=200)),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("token_prefix", models.CharField(blank=True, default="", max_length=12)),
                ("expires_at", models.DateTimeField()),
                ("one_time", models.BooleanField(default=False)),
                ("consumed_at", models.DateTimeField(blank=True, null=True)),
                ("view_count", models.IntegerField(default=0)),
                ("last_viewed_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "attachment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="share_links",
                        to="core.attachment",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_attachment_share_links",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attachment_share_links",
                        to="core.organization",
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["organization", "-created_at"], name="idx_core_attshare_org_recent"),
                    models.Index(fields=["attachment", "-created_at"], name="idx_core_attshare_att_recent"),
                    models.Index(fields=["expires_at"], name="idx_core_attshare_exp"),
                    models.Index(fields=["revoked_at"], name="idx_core_attshare_revoked"),
                    models.Index(fields=["consumed_at"], name="idx_core_attshare_consumed"),
                ],
            },
        ),
    ]
