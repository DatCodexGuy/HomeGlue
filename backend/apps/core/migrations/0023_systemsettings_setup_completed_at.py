from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0022_systemsettings_hosts_timeouts"),
    ]

    operations = [
        migrations.AddField(
            model_name="systemsettings",
            name="setup_completed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

