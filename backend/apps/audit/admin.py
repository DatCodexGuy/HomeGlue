from django.contrib import admin

from .models import AuditEvent, AuditPolicy


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    search_fields = ("model", "object_pk", "summary", "user__username")
    list_display = ("ts", "action", "model", "object_pk", "user", "ip")
    list_filter = ("action", "model")
    readonly_fields = ("ts",)


@admin.register(AuditPolicy)
class AuditPolicyAdmin(admin.ModelAdmin):
    list_display = ("organization", "enabled", "retention_days", "updated_at")
    list_filter = ("enabled",)
    search_fields = ("organization__name",)
