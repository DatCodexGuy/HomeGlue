from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0015_attachmentsharelink"),
    ]

    operations = [
        migrations.AlterField(
            model_name="savedview",
            name="model_key",
            field=models.CharField(
                choices=[
                    ("assets.asset", "Assets"),
                    ("assets.configurationitem", "Config Items"),
                    ("people.contact", "Contacts"),
                    ("core.location", "Locations"),
                    ("docsapp.document", "Docs"),
                    ("docsapp.documenttemplate", "Templates"),
                    ("secretsapp.passwordentry", "Passwords"),
                    ("netapp.domain", "Domains"),
                    ("netapp.sslcertificate", "SSL Certificates"),
                    ("core.attachment", "Files"),
                ],
                max_length=80,
            ),
        ),
    ]
