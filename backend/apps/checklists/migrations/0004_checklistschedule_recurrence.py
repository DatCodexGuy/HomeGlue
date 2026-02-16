from __future__ import annotations

from django.db import migrations, models


def _backfill_repeat_fields(apps, schema_editor):
    ChecklistSchedule = apps.get_model("checklists", "ChecklistSchedule")
    for s in ChecklistSchedule.objects.all().only("id", "every_days", "repeat_unit", "repeat_interval", "anchor_on", "next_run_on"):
        changed = False
        if not s.repeat_unit:
            s.repeat_unit = "daily"
            changed = True
        if not s.repeat_interval:
            s.repeat_interval = int(s.every_days or 7)
            changed = True
        if not s.anchor_on and s.next_run_on:
            s.anchor_on = s.next_run_on
            changed = True
        # Keep legacy every_days aligned for daily schedules.
        if s.repeat_unit == "daily" and int(s.every_days or 0) != int(s.repeat_interval or 0):
            s.every_days = int(s.repeat_interval or 1)
            changed = True
        if changed:
            s.save(update_fields=["repeat_unit", "repeat_interval", "anchor_on", "every_days"])


def _noop_reverse(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ("checklists", "0003_checklistrun_scheduled_for_checklistschedule_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="checklistschedule",
            name="repeat_unit",
            field=models.CharField(choices=[("daily", "Daily"), ("weekly", "Weekly"), ("monthly", "Monthly")], default="daily", max_length=16),
        ),
        migrations.AddField(
            model_name="checklistschedule",
            name="repeat_interval",
            field=models.IntegerField(default=7, help_text="Repeat every N units (days/weeks/months)."),
        ),
        migrations.AddField(
            model_name="checklistschedule",
            name="weekly_days",
            field=models.IntegerField(default=0, help_text="(Weekly) Weekday bitmask (Mon..Sun)."),
        ),
        migrations.AddField(
            model_name="checklistschedule",
            name="monthly_day",
            field=models.IntegerField(blank=True, help_text="(Monthly) Day of month (1-31).", null=True),
        ),
        migrations.AddField(
            model_name="checklistschedule",
            name="monthly_on_last_day",
            field=models.BooleanField(default=False, help_text="(Monthly) Run on the last day of the month."),
        ),
        migrations.AddField(
            model_name="checklistschedule",
            name="anchor_on",
            field=models.DateField(blank=True, help_text="Anchor date for weekly/monthly interval alignment.", null=True),
        ),
        migrations.RunPython(_backfill_repeat_fields, _noop_reverse),
    ]

