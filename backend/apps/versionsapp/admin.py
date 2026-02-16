from __future__ import annotations

from django.contrib import admin

from .models import ObjectVersion


@admin.register(ObjectVersion)
class ObjectVersionAdmin(admin.ModelAdmin):
    list_display = ("organization", "content_type", "object_id", "action", "created_by", "created_at")
    list_filter = ("organization", "content_type", "action")
    search_fields = ("object_id", "summary")
    ordering = ("-created_at",)

