from django.contrib import admin
from django.utils.html import format_html

from .models import PasswordEntry, PasswordFolder


@admin.register(PasswordEntry)
class PasswordEntryAdmin(admin.ModelAdmin):
    search_fields = ("name", "username", "url", "organization__name")
    list_display = ("name", "username", "organization", "updated_at", "created_at", "masked_password")
    list_filter = ("organization",)
    readonly_fields = ("updated_at", "created_at")
    list_select_related = ("organization",)
    autocomplete_fields = ("organization",)
    filter_horizontal = ("tags",)

    def masked_password(self, obj: PasswordEntry) -> str:
        if not obj.password_ciphertext:
            return ""
        return format_html("<code>********</code>")

    masked_password.short_description = "Password"


@admin.register(PasswordFolder)
class PasswordFolderAdmin(admin.ModelAdmin):
    search_fields = ("name", "organization__name")
    list_display = ("name", "parent", "organization", "archived_at", "updated_at")
    list_filter = ("organization", "archived_at")
    readonly_fields = ("updated_at", "created_at")
    list_select_related = ("organization", "parent")
    autocomplete_fields = ("organization", "parent")
