from __future__ import annotations

from django.contrib import admin

from .models import FlexibleAsset, FlexibleAssetType


@admin.register(FlexibleAssetType)
class FlexibleAssetTypeAdmin(admin.ModelAdmin):
    list_display = ("organization", "name", "archived", "sort_order", "updated_at")
    list_filter = ("organization", "archived")
    search_fields = ("name", "description")
    ordering = ("organization", "sort_order", "name")


@admin.register(FlexibleAsset)
class FlexibleAssetAdmin(admin.ModelAdmin):
    list_display = ("organization", "asset_type", "name", "updated_at")
    list_filter = ("organization", "asset_type")
    search_fields = ("name", "notes")
    ordering = ("organization", "asset_type", "name")

