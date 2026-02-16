from __future__ import annotations

from django.contrib import admin

from .models import Notification, WorkflowRule


@admin.register(WorkflowRule)
class WorkflowRuleAdmin(admin.ModelAdmin):
    list_display = ("organization", "name", "kind", "enabled", "audience", "run_interval_minutes", "last_run_at", "last_run_ok")
    list_filter = ("organization", "kind", "enabled", "audience")
    search_fields = ("name",)
    ordering = ("organization", "kind", "name")


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("organization", "user", "level", "title", "read_at", "created_at")
    list_filter = ("organization", "level")
    search_fields = ("title", "body", "dedupe_key")
    ordering = ("-created_at",)

