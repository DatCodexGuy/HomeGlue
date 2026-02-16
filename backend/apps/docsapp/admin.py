from django.contrib import admin

from .models import Document, DocumentTemplate


@admin.register(DocumentTemplate)
class DocumentTemplateAdmin(admin.ModelAdmin):
    search_fields = ("name", "organization__name")
    list_display = ("name", "organization", "created_at")
    list_filter = ("organization",)
    list_select_related = ("organization",)
    autocomplete_fields = ("organization",)
    filter_horizontal = ("tags",)


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    search_fields = ("title", "body", "organization__name")
    list_display = ("title", "organization", "updated_at", "created_at")
    list_filter = ("organization",)
    list_select_related = ("organization", "template")
    autocomplete_fields = ("organization", "template")
    filter_horizontal = ("tags",)
