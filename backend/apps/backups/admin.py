from __future__ import annotations

from django.contrib import admin

from .models import BackupPolicy, BackupRestoreBundle, BackupSnapshot


@admin.register(BackupSnapshot)
class BackupSnapshotAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "status", "filename", "bytes", "created_at", "started_at", "finished_at")
    list_filter = ("status", "organization")
    search_fields = ("filename", "organization__name")


@admin.register(BackupPolicy)
class BackupPolicyAdmin(admin.ModelAdmin):
    list_display = ("organization", "enabled", "interval_hours", "retention_count", "last_scheduled_at", "next_run_at", "updated_at")
    list_filter = ("enabled",)
    search_fields = ("organization__name",)


@admin.register(BackupRestoreBundle)
class BackupRestoreBundleAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "status", "filename", "bytes", "created_at", "validated_at", "media_extracted_at")
    list_filter = ("status", "organization")
    search_fields = ("filename", "organization__name")
    readonly_fields = ("created_at", "validated_at", "media_extracted_at", "sha256", "bytes", "manifest", "error")
