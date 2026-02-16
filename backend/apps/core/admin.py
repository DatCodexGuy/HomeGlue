from django.contrib import admin

from .admin_forms import RelationshipAdminForm
from .models import (
    Attachment,
    AttachmentVersion,
    FileFolder,
    Location,
    Note,
    Organization,
    OrganizationMembership,
    Relationship,
    RelationshipType,
    Tag,
    UserProfile,
)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    search_fields = ("name",)
    list_display = ("name", "created_at")


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    search_fields = ("name", "organization__name")
    list_display = ("name", "organization")
    list_filter = ("organization",)


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    search_fields = ("name", "organization__name")
    list_display = ("name", "organization")
    list_filter = ("organization",)
    autocomplete_fields = ("organization",)


@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    search_fields = ("title", "body", "organization__name")
    list_display = ("title", "organization", "created_at", "created_by")
    list_filter = ("organization",)


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    search_fields = ("filename", "organization__name")
    list_display = ("filename", "organization", "created_at", "uploaded_by")
    list_filter = ("organization",)


@admin.register(AttachmentVersion)
class AttachmentVersionAdmin(admin.ModelAdmin):
    search_fields = ("filename", "attachment__filename", "attachment__organization__name")
    list_display = ("filename", "attachment", "created_at", "uploaded_by", "bytes")
    list_filter = ("attachment__organization",)


@admin.register(FileFolder)
class FileFolderAdmin(admin.ModelAdmin):
    search_fields = ("name", "organization__name")
    list_display = ("name", "organization", "parent", "archived_at", "created_at", "updated_at")
    list_filter = ("organization",)


@admin.register(RelationshipType)
class RelationshipTypeAdmin(admin.ModelAdmin):
    search_fields = ("name", "inverse_name", "organization__name")
    list_display = ("name", "inverse_name", "symmetric", "organization", "created_at")
    list_filter = ("organization", "symmetric")


@admin.register(Relationship)
class RelationshipAdmin(admin.ModelAdmin):
    form = RelationshipAdminForm
    search_fields = ("notes", "organization__name")
    list_display = ("organization", "relationship_type", "source_pretty", "target_pretty", "created_at", "created_by")
    list_filter = ("organization", "relationship_type")
    readonly_fields = ("created_at",)

    def source_pretty(self, obj: Relationship) -> str:
        return obj.source_label()

    def target_pretty(self, obj: Relationship) -> str:
        return obj.target_label()

    source_pretty.short_description = "Source"
    target_pretty.short_description = "Target"

    def save_model(self, request, obj: Relationship, form, change):
        if not obj.created_by_id and request.user and request.user.is_authenticated:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(OrganizationMembership)
class OrganizationMembershipAdmin(admin.ModelAdmin):
    search_fields = ("user__username", "user__email", "organization__name")
    list_display = ("user", "organization", "role", "created_at")
    list_filter = ("organization", "role")
    autocomplete_fields = ("user", "organization")
    readonly_fields = ("created_at",)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    search_fields = ("user__username", "user__email", "default_organization__name")
    list_display = ("user", "default_organization", "updated_at")
    autocomplete_fields = ("user", "default_organization")
    readonly_fields = ("updated_at",)
