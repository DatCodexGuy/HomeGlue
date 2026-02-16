from django.contrib import admin

from .models import Asset, ConfigurationItem


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    search_fields = ("name", "manufacturer", "model", "serial_number", "organization__name")
    list_display = ("name", "asset_type", "manufacturer", "model", "organization", "location")
    list_filter = ("organization", "asset_type")
    list_select_related = ("organization", "location")
    autocomplete_fields = ("organization", "location")
    filter_horizontal = ("tags",)


@admin.register(ConfigurationItem)
class ConfigurationItemAdmin(admin.ModelAdmin):
    search_fields = ("name", "hostname", "primary_ip", "organization__name")
    list_display = ("name", "ci_type", "hostname", "primary_ip", "organization")
    list_filter = ("organization", "ci_type")
    list_select_related = ("organization",)
    autocomplete_fields = ("organization",)
    filter_horizontal = ("tags",)
