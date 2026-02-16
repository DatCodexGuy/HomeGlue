from __future__ import annotations

from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.workflows"

    def ready(self):
        # Register signals (org-created seeding for default rules).
        from . import signals  # noqa: F401
