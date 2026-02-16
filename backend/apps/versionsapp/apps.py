from __future__ import annotations

from django.apps import AppConfig


class VersionsAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.versionsapp"

    def ready(self):
        # Register signals.
        from . import signals  # noqa: F401

