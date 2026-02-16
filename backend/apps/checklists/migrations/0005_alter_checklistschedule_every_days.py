from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("checklists", "0004_checklistschedule_recurrence"),
    ]

    operations = [
        migrations.AlterField(
            model_name="checklistschedule",
            name="every_days",
            field=models.IntegerField(default=7, help_text="(Legacy) Create a run every N days."),
        ),
    ]

