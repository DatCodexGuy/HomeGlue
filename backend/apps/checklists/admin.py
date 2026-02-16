from __future__ import annotations

from django.contrib import admin

from .models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem


@admin.register(Checklist)
class ChecklistAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "name", "archived_at", "updated_at")
    search_fields = ("name", "description")
    list_filter = ("archived_at", "organization")


@admin.register(ChecklistItem)
class ChecklistItemAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "checklist", "is_done", "sort_order", "updated_at")
    search_fields = ("text",)
    list_filter = ("is_done", "organization")


@admin.register(ChecklistRun)
class ChecklistRunAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "name", "status", "due_on", "checklist", "assigned_to", "updated_at")
    search_fields = ("name",)
    list_filter = ("organization", "status")
    list_select_related = ("organization", "checklist", "assigned_to")
    autocomplete_fields = ("organization", "checklist", "assigned_to", "created_by")


@admin.register(ChecklistRunItem)
class ChecklistRunItemAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "run", "is_done", "sort_order", "updated_at")
    search_fields = ("text",)
    list_filter = ("organization", "is_done")
    list_select_related = ("organization", "run")
