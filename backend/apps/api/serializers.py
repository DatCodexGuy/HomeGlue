from __future__ import annotations

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import CustomField, CustomFieldValue, Location, Organization, Tag
from apps.core.models import Relationship, RelationshipType
from apps.docsapp.models import Document, DocumentFolder, DocumentTemplate
from apps.netapp.models import Domain, SSLCertificate
from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem, ChecklistSchedule
from apps.people.models import Contact
from apps.secretsapp.models import PasswordEntry, PasswordFolder
from apps.flexassets.models import FlexibleAsset, FlexibleAssetType
from django.contrib.contenttypes.models import ContentType
from apps.workflows.models import Notification, WebhookEndpoint, WorkflowRule


def _parse_ref(ref: str):
    ref = (ref or "").strip()
    if not ref or ":" not in ref or "." not in ref:
        raise ValidationError('Invalid ref. Expected "app_label.model:pk".')
    left, pk = ref.split(":", 1)
    pk = pk.strip()
    app_label, model = left.split(".", 1)
    app_label = app_label.strip()
    model = model.strip()
    try:
        ct = ContentType.objects.get(app_label=app_label, model=model)
    except ContentType.DoesNotExist as e:
        raise ValidationError(f"Unknown content type: {app_label}.{model}") from e
    model_cls = ct.model_class()
    if model_cls is None:
        raise ValidationError(f"Content type has no model class: {app_label}.{model}")
    try:
        obj = model_cls.objects.get(pk=pk)
    except model_cls.DoesNotExist as e:
        raise ValidationError(f"Object not found: {app_label}.{model}:{pk}") from e
    return ct, str(obj.pk), str(obj)


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "name", "description", "created_at"]


class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ["id", "organization", "name", "address", "archived_at"]
        extra_kwargs = {"organization": {"required": False}}


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["id", "organization", "name"]
        extra_kwargs = {"organization": {"required": False}}


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = [
            "id",
            "organization",
            "first_name",
            "last_name",
            "email",
            "phone",
            "title",
            "notes",
            "tags",
            "archived_at",
            "created_at",
        ]
        extra_kwargs = {"organization": {"required": False}}


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = [
            "id",
            "organization",
            "name",
            "asset_type",
            "manufacturer",
            "model",
            "serial_number",
            "location",
            "notes",
            "tags",
            "archived_at",
            "created_at",
        ]
        extra_kwargs = {"organization": {"required": False}}


class ConfigurationItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfigurationItem
        fields = [
            "id",
            "organization",
            "name",
            "ci_type",
            "hostname",
            "primary_ip",
            "operating_system",
            "notes",
            "tags",
            "archived_at",
            "created_at",
        ]
        extra_kwargs = {"organization": {"required": False}}


class DocumentTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentTemplate
        fields = ["id", "organization", "name", "body", "tags", "archived_at", "created_at"]
        extra_kwargs = {"organization": {"required": False}}


class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = [
            "id",
            "organization",
            "created_by",
            "visibility",
            "allowed_users",
            "title",
            "folder",
            "body",
            "template",
            "tags",
            "flagged_at",
            "flagged_by",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {
            "organization": {"required": False},
            "created_by": {"read_only": True},
            "allowed_users": {"required": False},
            "flagged_by": {"read_only": True},
        }


class DocumentFolderSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = DocumentFolder
        fields = ["id", "organization", "name", "parent", "archived_at", "updated_at", "created_at"]


class PasswordEntrySerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    has_password = serializers.SerializerMethodField()
    has_totp = serializers.SerializerMethodField()
    rotation_due_on = serializers.SerializerMethodField()
    rotation_overdue = serializers.SerializerMethodField()

    class Meta:
        model = PasswordEntry
        fields = [
            "id",
            "organization",
            "created_by",
            "visibility",
            "allowed_users",
            "name",
            "folder",
            "username",
            "password",
            "has_password",
            "has_totp",
            "url",
            "notes",
            "rotation_interval_days",
            "last_changed_at",
            "rotation_due_on",
            "rotation_overdue",
            "tags",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {
            "organization": {"required": False},
            "created_by": {"read_only": True},
            "allowed_users": {"required": False},
        }

    def get_has_password(self, obj: PasswordEntry) -> bool:
        return bool(obj.password_ciphertext)

    def get_has_totp(self, obj: PasswordEntry) -> bool:
        return bool(getattr(obj, "totp_secret_ciphertext", ""))

    def get_rotation_due_on(self, obj: PasswordEntry):
        try:
            d = obj.rotation_due_on()
            return d.isoformat() if d else None
        except Exception:
            return None

    def get_rotation_overdue(self, obj: PasswordEntry) -> bool:
        try:
            d = obj.rotation_due_on()
            if not d:
                return False
            from datetime import date

            return d < date.today()
        except Exception:
            return False

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        obj = super().create(validated_data)
        if password is not None:
            obj.set_password(password)
            obj.save(update_fields=["password_ciphertext", "last_changed_at"])
        return obj

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        obj = super().update(instance, validated_data)
        if password is not None:
            obj.set_password(password)
            obj.save(update_fields=["password_ciphertext", "last_changed_at"])
        return obj


class PasswordFolderSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordFolder
        fields = ["id", "organization", "name", "parent", "archived_at", "updated_at", "created_at"]
        extra_kwargs = {"organization": {"required": False}}


class RelationshipTypeSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = RelationshipType
        fields = ["id", "organization", "name", "inverse_name", "symmetric", "created_at"]


class RelationshipSerializer(serializers.ModelSerializer):
    # Required on create; optional on update.
    source_ref = serializers.CharField(write_only=True, required=False)
    target_ref = serializers.CharField(write_only=True, required=False)

    source = serializers.SerializerMethodField()
    target = serializers.SerializerMethodField()

    class Meta:
        model = Relationship
        fields = [
            "id",
            "organization",
            "relationship_type",
            "source_ref",
            "target_ref",
            "source",
            "target",
            "notes",
            "created_by",
            "created_at",
        ]
        read_only_fields = ["created_by", "created_at", "source", "target"]
        extra_kwargs = {"organization": {"required": False}}

    def get_source(self, obj: Relationship):
        ct = obj.source_content_type
        return {
            "ref": f"{ct.app_label}.{ct.model}:{obj.source_object_id}",
            "label": obj.source_label(),
        }

    def get_target(self, obj: Relationship):
        ct = obj.target_content_type
        return {
            "ref": f"{ct.app_label}.{ct.model}:{obj.target_object_id}",
            "label": obj.target_label(),
        }

    def validate(self, attrs):
        src_ref = attrs.get("source_ref")
        tgt_ref = attrs.get("target_ref")

        if self.instance is None:
            if not src_ref or not tgt_ref:
                raise ValidationError({"source_ref": "Required.", "target_ref": "Required."})

        if src_ref:
            src_ct, src_id, _ = _parse_ref(src_ref)
            attrs["source_content_type"] = src_ct
            attrs["source_object_id"] = src_id

        if tgt_ref:
            tgt_ct, tgt_id, _ = _parse_ref(tgt_ref)
            attrs["target_content_type"] = tgt_ct
            attrs["target_object_id"] = tgt_id

        if (
            attrs.get("source_content_type")
            and attrs.get("target_content_type")
            and str(attrs.get("source_object_id")) == str(attrs.get("target_object_id"))
            and int(attrs.get("source_content_type").id) == int(attrs.get("target_content_type").id)
        ):
            raise ValidationError("Relationship cannot point to the same object.")

        org = attrs.get("organization") or getattr(self.instance, "organization", None)
        rel_type = attrs.get("relationship_type") or getattr(self.instance, "relationship_type", None)
        if org is not None and rel_type is not None:
            if int(rel_type.organization_id) != int(org.id):
                raise ValidationError({"relationship_type": "Relationship type organization must match relationship organization."})

        return attrs

    def create(self, validated_data):
        validated_data.pop("source_ref", None)
        validated_data.pop("target_ref", None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data.pop("source_ref", None)
        validated_data.pop("target_ref", None)
        return super().update(instance, validated_data)


class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = [
            "id",
            "organization",
            "name",
            "status",
            "registrar",
            "dns_provider",
            "expires_on",
            "auto_renew",
            "notes",
            "tags",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {"organization": {"required": False}}


class SSLCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLCertificate
        fields = [
            "id",
            "organization",
            "common_name",
            "subject_alt_names",
            "issuer",
            "serial_number",
            "fingerprint_sha256",
            "not_before",
            "not_after",
            "domains",
            "notes",
            "tags",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {"organization": {"required": False}}


class ChecklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Checklist
        fields = ["id", "organization", "name", "description", "tags", "archived_at", "updated_at", "created_at"]
        extra_kwargs = {"organization": {"required": False}}


class ChecklistItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChecklistItem
        fields = ["id", "organization", "checklist", "text", "is_done", "sort_order", "updated_at", "created_at"]
        extra_kwargs = {"organization": {"required": False}}


class ChecklistRunSerializer(serializers.ModelSerializer):
    ref = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = ChecklistRun
        fields = [
            "id",
            "organization",
            "checklist",
            "name",
            "status",
            "due_on",
            "started_at",
            "completed_at",
            "created_by",
            "assigned_to",
            "ref",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {
            "organization": {"required": False},
            "created_by": {"read_only": True},
            "started_at": {"required": False, "allow_null": True},
            "completed_at": {"required": False, "allow_null": True},
        }


class ChecklistRunItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChecklistRunItem
        fields = [
            "id",
            "organization",
            "run",
            "checklist_item",
            "text",
            "is_done",
            "sort_order",
            "done_at",
            "done_by",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {
            "organization": {"required": False},
            "done_at": {"required": False, "allow_null": True},
            "done_by": {"read_only": True},
        }


class ChecklistScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChecklistSchedule
        fields = [
            "id",
            "organization",
            "checklist",
            "name",
            "enabled",
            "every_days",
            "due_days",
            "assigned_to",
            "next_run_on",
            "last_created_at",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {
            "organization": {"required": False},
            "last_created_at": {"read_only": True},
            "archived_at": {"required": False, "allow_null": True},
        }


class WorkflowRuleSerializer(serializers.ModelSerializer):
    days = serializers.IntegerField(required=False, min_value=1, max_value=3650)

    class Meta:
        model = WorkflowRule
        fields = [
            "id",
            "organization",
            "name",
            "enabled",
            "kind",
            "audience",
            "days",
            "run_interval_minutes",
            "last_run_at",
            "last_run_ok",
            "last_run_error",
            "created_at",
            "updated_at",
        ]
        extra_kwargs = {
            "organization": {"required": False},
            "last_run_at": {"read_only": True},
            "last_run_ok": {"read_only": True},
            "last_run_error": {"read_only": True},
        }

    def _apply_days(self, obj, *, validated_data):
        if "days" not in validated_data:
            return
        params = dict(getattr(obj, "params", None) or {})
        d = validated_data.pop("days", None)
        if d is not None:
            params["days"] = int(d)
        obj.params = params

    def create(self, validated_data):
        obj = WorkflowRule(**{k: v for k, v in validated_data.items() if k != "days"})
        self._apply_days(obj, validated_data=validated_data)
        obj.save()
        return obj

    def update(self, instance, validated_data):
        self._apply_days(instance, validated_data=validated_data)
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        try:
            data["days"] = int((instance.params or {}).get("days") or 0) or None
        except Exception:
            data["days"] = None
        return data


class NotificationSerializer(serializers.ModelSerializer):
    ref = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            "id",
            "organization",
            "user",
            "level",
            "title",
            "body",
            "rule",
            "ref",
            "read_at",
            "created_at",
        ]
        read_only_fields = ["user", "ref", "created_at"]
        extra_kwargs = {"organization": {"required": False}}

    def get_ref(self, obj: Notification):
        if obj.content_type_id and obj.object_id:
            ct = obj.content_type
            return f"{ct.app_label}.{ct.model}:{obj.object_id}"
        return None


class WebhookEndpointSerializer(serializers.ModelSerializer):
    secret = serializers.CharField(write_only=True, required=False, allow_blank=True)
    has_secret = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEndpoint
        fields = ["id", "organization", "name", "url", "verify_ssl", "enabled", "secret", "has_secret", "created_at", "updated_at"]
        extra_kwargs = {"organization": {"required": False}}

    def get_has_secret(self, obj: WebhookEndpoint) -> bool:
        return bool(getattr(obj, "secret_ciphertext", "") or "")

    def create(self, validated_data):
        secret = (validated_data.pop("secret", None) or "").strip()
        obj = super().create(validated_data)
        if secret:
            obj.set_secret(secret)
            obj.save(update_fields=["secret_ciphertext"])
        return obj

    def update(self, instance, validated_data):
        secret = (validated_data.pop("secret", None) or "").strip()
        obj = super().update(instance, validated_data)
        if secret:
            obj.set_secret(secret)
            obj.save(update_fields=["secret_ciphertext"])
        return obj


class SearchResultSerializer(serializers.Serializer):
    type = serializers.CharField()
    id = serializers.IntegerField()
    label = serializers.CharField()


class SearchResponseSerializer(serializers.Serializer):
    results = SearchResultSerializer(many=True)


class MeSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    is_superuser = serializers.BooleanField()
    member_org_ids = serializers.ListField(child=serializers.IntegerField())
    default_org_id = serializers.IntegerField(allow_null=True, required=False)


class DefaultOrgRequestSerializer(serializers.Serializer):
    organization = serializers.IntegerField(required=False)
    org = serializers.IntegerField(required=False)


class ApiTokenStatusSerializer(serializers.Serializer):
    has_token = serializers.BooleanField()


class ApiTokenRotateSerializer(serializers.Serializer):
    token = serializers.CharField()


class ReauthRequestSerializer(serializers.Serializer):
    password = serializers.CharField()


class ReauthResponseSerializer(serializers.Serializer):
    token = serializers.CharField()
    expires_in = serializers.IntegerField()


class CustomFieldSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CustomField
        fields = [
            "id",
            "organization",
            "content_type",
            "flexible_asset_type",
            "key",
            "name",
            "field_type",
            "required",
            "help_text",
            "sort_order",
            "created_at",
        ]
        extra_kwargs = {
            "flexible_asset_type": {"required": False, "allow_null": True},
        }


class FlexibleAssetTypeSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = FlexibleAssetType
        fields = [
            "id",
            "organization",
            "name",
            "description",
            "icon",
            "color",
            "sort_order",
            "archived",
            "updated_at",
            "created_at",
        ]


class FlexibleAssetSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = FlexibleAsset
        fields = [
            "id",
            "organization",
            "asset_type",
            "name",
            "notes",
            "tags",
            "archived_at",
            "updated_at",
            "created_at",
        ]
        extra_kwargs = {"organization": {"required": False}}


class CustomFieldValueSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(read_only=True)
    content_type = serializers.PrimaryKeyRelatedField(queryset=ContentType.objects.all(), required=False)
    object_id = serializers.CharField(required=False)

    # Optional convenience input (preferred): "app_label.model:pk"
    ref = serializers.CharField(write_only=True, required=False)
    obj = serializers.SerializerMethodField()

    class Meta:
        model = CustomFieldValue
        fields = [
            "id",
            "organization",
            "field",
            "content_type",
            "object_id",
            "ref",
            "obj",
            "value_text",
            "updated_at",
            "created_at",
        ]
        read_only_fields = ["updated_at", "created_at", "obj", "organization"]

    def get_obj(self, obj: CustomFieldValue):
        ct = obj.content_type
        return {"ref": f"{ct.app_label}.{ct.model}:{obj.object_id}"}

    def validate(self, attrs):
        ref = attrs.get("ref")
        if ref:
            ct, obj_id, _ = _parse_ref(ref)
            attrs["content_type"] = ct
            attrs["object_id"] = obj_id
        if self.instance is None:
            if not attrs.get("content_type") or not attrs.get("object_id"):
                raise ValidationError({"ref": "Required (or provide content_type + object_id)."})
        return attrs

    def create(self, validated_data):
        validated_data.pop("ref", None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data.pop("ref", None)
        return super().update(instance, validated_data)
