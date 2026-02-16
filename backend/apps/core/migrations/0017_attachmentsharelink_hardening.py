from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0016_alter_savedview_model_key"),
    ]

    operations = [
        migrations.AddField(
            model_name="attachmentsharelink",
            name="max_downloads",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="attachmentsharelink",
            name="passphrase_hash",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
