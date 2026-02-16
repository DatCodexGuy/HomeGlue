from django.contrib import admin

from .models import AuditEvent


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    search_fields = ("model", "object_pk", "summary", "user__username")
    list_display = ("ts", "action", "model", "object_pk", "user", "ip")
    list_filter = ("action", "model")
    readonly_fields = ("ts",)

