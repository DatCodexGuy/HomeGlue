from __future__ import annotations

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0003_alter_asset_unique_together_and_more"),
        ("integrations", "0005_proxmoxguest_agent_hostname_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="proxmoxguest",
            name="asset",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="proxmox_guest",
                to="assets.asset",
            ),
        ),
        migrations.AddField(
            model_name="proxmoxnode",
            name="asset",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="proxmox_node",
                to="assets.asset",
            ),
        ),
        migrations.AddField(
            model_name="proxmoxnode",
            name="config_item",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="proxmox_node",
                to="assets.configurationitem",
            ),
        ),
    ]

