from __future__ import annotations

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("workflows", "0003_alter_workflowrule_kind"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="WorkflowRuleRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "triggered_by",
                    models.CharField(
                        choices=[("worker", "Worker"), ("manual", "Manual"), ("ops", "Ops")],
                        default="worker",
                        max_length=16,
                    ),
                ),
                ("started_at", models.DateTimeField()),
                ("finished_at", models.DateTimeField()),
                ("duration_ms", models.IntegerField(default=0)),
                ("ok", models.BooleanField(default=False)),
                ("notifications_created", models.IntegerField(default=0)),
                ("error", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "organization",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="workflow_rule_runs", to="core.organization"),
                ),
                (
                    "rule",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="runs",
                        to="workflows.workflowrule",
                    ),
                ),
                (
                    "triggered_by_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="triggered_workflow_rule_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["organization", "-started_at"], name="idx_wf_rule_run_org_recent"),
                    models.Index(fields=["organization", "rule", "-started_at"], name="idx_wf_rule_run_rule_recent"),
                    models.Index(fields=["organization", "ok", "-started_at"], name="idx_wf_rule_run_ok_recent"),
                ],
            },
        ),
    ]

