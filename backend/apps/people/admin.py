from django.contrib import admin

from .models import Contact


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    search_fields = ("first_name", "last_name", "email", "organization__name")
    list_display = ("first_name", "last_name", "email", "phone", "organization")
    list_filter = ("organization",)
    list_select_related = ("organization",)
    autocomplete_fields = ("organization",)
    filter_horizontal = ("tags",)
