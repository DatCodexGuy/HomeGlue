from __future__ import annotations

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError

from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import CustomField, FileFolder, Location, OrganizationMembership, Relationship, RelationshipType, SavedView, Tag
from apps.docsapp.models import Document, DocumentComment, DocumentFolder, DocumentTemplate, DocumentTemplateComment
from apps.netapp.models import Domain, SSLCertificate
from apps.checklists.models import Checklist, ChecklistRun, ChecklistSchedule
from apps.people.models import Contact
from apps.secretsapp.models import PasswordEntry
from apps.secretsapp.models import PasswordFolder
from apps.integrations.models import ProxmoxConnection
from apps.flexassets.models import FlexibleAsset, FlexibleAssetType
from apps.workflows.models import WebhookEndpoint, WorkflowRule


def tags_queryset_for_org(org):
    return Tag.objects.filter(organization__isnull=True) | Tag.objects.filter(organization=org)


def _folder_path_labels(*, folders) -> dict[int, dict[str, object]]:
    """
    Build stable display labels for nested folders without extra queries.
    Returns: {id: {"path": "A / B", "depth": 1}}
    """

    by_id = {int(f.id): f for f in folders if getattr(f, "id", None)}
    memo: dict[int, list[str]] = {}

    def _path(fid: int) -> list[str]:
        if fid in memo:
            return memo[fid]
        f = by_id.get(int(fid))
        if not f:
            memo[fid] = []
            return memo[fid]
        pid = getattr(f, "parent_id", None)
        if pid and int(pid) in by_id:
            memo[fid] = _path(int(pid)) + [str(getattr(f, "name", "") or "")]
        else:
            memo[fid] = [str(getattr(f, "name", "") or "")]
        return memo[fid]

    out = {}
    for fid in list(by_id.keys()):
        parts = [p for p in _path(fid) if p]
        out[fid] = {"path": " / ".join(parts), "depth": max(0, len(parts) - 1)}
    return out


class OrgBoundModelForm(forms.ModelForm):
    """
    Base form that expects `org` passed in to scope querysets.
    """

    def __init__(self, *args, org=None, **kwargs):
        self.org = org
        super().__init__(*args, **kwargs)


class AssetForm(OrgBoundModelForm):
    new_location_name = forms.CharField(required=False, help_text="Optional: create a new location and assign it.")
    new_location_address = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}))

    class Meta:
        model = Asset
        fields = [
            "name",
            "asset_type",
            "manufacturer",
            "model",
            "serial_number",
            "location",
            "new_location_name",
            "new_location_address",
            "tags",
            "notes",
        ]
        widgets = {"notes": forms.Textarea(attrs={"rows": 6, "class": "js-md"})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["location"].queryset = Location.objects.filter(organization=self.org).order_by("name")
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")
        self.fields["new_location_address"].label = "New location address"

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("location") and cleaned.get("new_location_name"):
            self.add_error("new_location_name", "Choose a location or create a new one, not both.")
        return cleaned

    def save(self, commit=True):
        obj = super().save(commit=False)
        name = (self.cleaned_data.get("new_location_name") or "").strip()
        addr = (self.cleaned_data.get("new_location_address") or "").strip()
        if self.org and name:
            loc, _ = Location.objects.get_or_create(organization=self.org, name=name, defaults={"address": addr})
            if addr and loc.address != addr:
                loc.address = addr
                loc.save(update_fields=["address"])
            obj.location = loc
        if commit:
            obj.save()
            self.save_m2m()
        return obj


class ConfigurationItemForm(OrgBoundModelForm):
    class Meta:
        model = ConfigurationItem
        fields = ["name", "ci_type", "hostname", "primary_ip", "operating_system", "tags", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 6, "class": "js-md"})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")


class DocumentTemplateForm(OrgBoundModelForm):
    class Meta:
        model = DocumentTemplate
        fields = ["name", "body", "tags"]
        widgets = {"body": forms.Textarea(attrs={"rows": 14, "class": "js-md"})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")


class DocumentForm(OrgBoundModelForm):
    class Meta:
        model = Document
        fields = ["title", "folder", "visibility", "allowed_users", "template", "body", "tags"]
        widgets = {"body": forms.Textarea(attrs={"rows": 14, "class": "js-md"})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            folder_qs = DocumentFolder.objects.filter(organization=self.org, archived_at__isnull=True).order_by("parent_id", "name")
            self.fields["folder"].queryset = folder_qs
            # Render nested folders with a stable "path" label.
            folders = list(folder_qs[:5000])
            labels = _folder_path_labels(folders=folders)

            def _lbl(obj):
                info = labels.get(int(obj.id), None)
                if not info:
                    return str(getattr(obj, "name", "") or "")
                depth = int(info.get("depth") or 0)
                prefix = ("  " * depth) + ("- " if depth else "")
                return prefix + str(info.get("path") or obj.name)

            self.fields["folder"].label_from_instance = _lbl
            self.fields["template"].queryset = DocumentTemplate.objects.filter(organization=self.org).order_by("name")
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")
            User = get_user_model()
            member_ids = OrganizationMembership.objects.filter(organization=self.org).values_list("user_id", flat=True)
            self.fields["allowed_users"].queryset = User.objects.filter(id__in=member_ids).order_by("username")
            self.fields["allowed_users"].required = False
        self.fields["allowed_users"].help_text = "Only used when visibility is Shared."

    def clean(self):
        cleaned = super().clean()
        vis = cleaned.get("visibility")
        allowed = cleaned.get("allowed_users")
        if vis != Document.VIS_SHARED and allowed:
            self.add_error("allowed_users", "Allowed users only applies when visibility is Shared.")
        return cleaned

    def save(self, commit=True):
        obj = super().save(commit=False)
        if self.cleaned_data.get("visibility") != Document.VIS_SHARED:
            obj._clear_allowed_users = True
        if commit:
            obj.save()
            self.save_m2m()
            if getattr(obj, "_clear_allowed_users", False):
                obj.allowed_users.clear()
        return obj


class DocumentCommentForm(OrgBoundModelForm):
    class Meta:
        model = DocumentComment
        fields = ["body"]
        widgets = {"body": forms.Textarea(attrs={"rows": 4, "class": "js-md"})}

    def clean_body(self):
        return (self.cleaned_data.get("body") or "").strip()


class DocumentTemplateCommentForm(OrgBoundModelForm):
    class Meta:
        model = DocumentTemplateComment
        fields = ["body"]
        widgets = {"body": forms.Textarea(attrs={"rows": 4, "class": "js-md"})}

    def clean_body(self):
        return (self.cleaned_data.get("body") or "").strip()


class DocumentFolderForm(OrgBoundModelForm):
    class Meta:
        model = DocumentFolder
        fields = ["name", "parent"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            parent_qs = DocumentFolder.objects.filter(organization=self.org, archived_at__isnull=True).order_by("parent_id", "name")
            self.fields["parent"].queryset = parent_qs
            folders = list(parent_qs[:5000])
            labels = _folder_path_labels(folders=folders)

            def _lbl(obj):
                info = labels.get(int(obj.id), None)
                if not info:
                    return str(getattr(obj, "name", "") or "")
                depth = int(info.get("depth") or 0)
                prefix = ("  " * depth) + ("- " if depth else "")
                return prefix + str(info.get("path") or obj.name)

            self.fields["parent"].label_from_instance = _lbl

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()

    def clean(self):
        cleaned = super().clean()
        parent = cleaned.get("parent")
        if not parent:
            return cleaned
        if self.instance and getattr(self.instance, "id", None) and int(parent.id) == int(self.instance.id):
            self.add_error("parent", "A folder cannot be its own parent.")
            return cleaned
        # Prevent cycles: walk up the parent chain.
        cur = parent
        seen = set()
        while cur is not None and getattr(cur, "id", None):
            cid = int(cur.id)
            if cid in seen:
                break
            seen.add(cid)
            if self.instance and getattr(self.instance, "id", None) and cid == int(self.instance.id):
                self.add_error("parent", "Invalid parent (would create a cycle).")
                break
            cur = getattr(cur, "parent", None)
        return cleaned


class PasswordEntryForm(OrgBoundModelForm):
    password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))

    class Meta:
        model = PasswordEntry
        fields = [
            "name",
            "folder",
            "visibility",
            "allowed_users",
            "username",
            "url",
            "password",
            "rotation_interval_days",
            "tags",
            "notes",
        ]
        widgets = {"notes": forms.Textarea(attrs={"rows": 6, "class": "js-md"})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")
            self.fields["folder"].queryset = PasswordFolder.objects.filter(organization=self.org, archived_at__isnull=True).order_by("parent_id", "name")
            User = get_user_model()
            member_ids = OrganizationMembership.objects.filter(organization=self.org).values_list("user_id", flat=True)
            self.fields["allowed_users"].queryset = User.objects.filter(id__in=member_ids).order_by("username")
            self.fields["allowed_users"].required = False
        self.fields["allowed_users"].help_text = "Only used when visibility is Shared."
        self.fields["rotation_interval_days"].help_text = "0 = no rotation reminders. Example: 90 for quarterly rotation."

    def clean(self):
        cleaned = super().clean()
        vis = cleaned.get("visibility")
        allowed = cleaned.get("allowed_users")
        if vis != PasswordEntry.VIS_SHARED and allowed:
            self.add_error("allowed_users", "Allowed users only applies when visibility is Shared.")
        return cleaned


class FileFolderForm(OrgBoundModelForm):
    class Meta:
        model = FileFolder
        fields = ["name", "parent"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            parent_qs = FileFolder.objects.filter(organization=self.org, archived_at__isnull=True).order_by("parent_id", "name")
            self.fields["parent"].queryset = parent_qs
            folders = list(parent_qs[:5000])
            labels = _folder_path_labels(folders=folders)

            def _lbl(obj):
                info = labels.get(int(obj.id), None)
                if not info:
                    return str(getattr(obj, "name", "") or "")
                depth = int(info.get("depth") or 0)
                prefix = ("  " * depth) + ("- " if depth else "")
                return prefix + str(info.get("path") or obj.name)

            self.fields["parent"].label_from_instance = _lbl

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()

    def clean(self):
        cleaned = super().clean()
        parent = cleaned.get("parent")
        if not parent:
            return cleaned
        if self.instance and getattr(self.instance, "id", None) and int(parent.id) == int(self.instance.id):
            self.add_error("parent", "A folder cannot be its own parent.")
            return cleaned
        cur = parent
        seen = set()
        while cur is not None and getattr(cur, "id", None):
            cid = int(cur.id)
            if cid in seen:
                break
            seen.add(cid)
            if self.instance and getattr(self.instance, "id", None) and cid == int(self.instance.id):
                self.add_error("parent", "Invalid parent (would create a cycle).")
                break
            cur = getattr(cur, "parent", None)
        return cleaned

    def save(self, commit=True):
        obj = super().save(commit=False)
        pw = self.cleaned_data.get("password")
        if pw:
            obj.set_password(pw)
        if self.cleaned_data.get("visibility") != PasswordEntry.VIS_SHARED:
            # Ensure stale shares don't linger when switching away from Shared.
            obj._clear_allowed_users = True
        if commit:
            obj.save()
            self.save_m2m()
            if getattr(obj, "_clear_allowed_users", False):
                obj.allowed_users.clear()
        return obj


class PasswordFolderForm(OrgBoundModelForm):
    class Meta:
        model = PasswordFolder
        fields = ["name", "parent"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["parent"].queryset = PasswordFolder.objects.filter(organization=self.org, archived_at__isnull=True).order_by("parent_id", "name")

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()


class ReauthForm(forms.Form):
    password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "current-password"}),
        help_text="Confirm your password to continue.",
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_password(self):
        pw = self.cleaned_data.get("password") or ""
        if not self.user or not getattr(self.user, "is_authenticated", False):
            raise ValidationError("Not authenticated.")
        if not getattr(self.user, "has_usable_password", lambda: True)():
            raise ValidationError("This account does not have a local password (SSO-only). Re-auth is not supported yet.")
        if not self.user.check_password(pw):
            raise ValidationError("Incorrect password.")
        return pw


class RelationshipForm(OrgBoundModelForm):
    source_ref = forms.CharField(help_text='Format: "app_label.model:pk" (e.g. assets.asset:1)')
    target_ref = forms.CharField(help_text='Format: "app_label.model:pk" (e.g. docsapp.document:3)')

    class Meta:
        model = Relationship
        fields = ["relationship_type", "source_ref", "target_ref", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 5})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["relationship_type"].queryset = RelationshipType.objects.filter(organization=self.org).order_by("name")

    def _parse_ref(self, ref: str):
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
        return ct, str(obj.pk), obj

    def clean(self):
        cleaned = super().clean()
        if not self.org:
            return cleaned

        src_ref = cleaned.get("source_ref")
        tgt_ref = cleaned.get("target_ref")
        if not src_ref or not tgt_ref:
            return cleaned

        src_ct, src_id, src_obj = self._parse_ref(src_ref)
        tgt_ct, tgt_id, tgt_obj = self._parse_ref(tgt_ref)
        if src_ct.id == tgt_ct.id and str(src_id) == str(tgt_id):
            raise ValidationError("Relationship cannot point to the same object.")

        def _org_id_for_obj(obj):
            org_id = getattr(obj, "organization_id", None)
            if org_id is not None:
                return int(org_id)
            # Integrations models are often scoped via `connection -> organization`.
            conn = getattr(obj, "connection", None)
            if conn is not None and getattr(conn, "organization_id", None) is not None:
                return int(conn.organization_id)
            return None

        # Prevent cross-org refs when objects are org-scoped (directly or via a connection FK).
        for side, obj in [("source_ref", src_obj), ("target_ref", tgt_obj)]:
            obj_org_id = _org_id_for_obj(obj)
            if obj_org_id is not None and int(obj_org_id) != int(self.org.id):
                self.add_error(side, "Referenced object must belong to the current organization.")

        cleaned["_src_ct"] = src_ct
        cleaned["_src_id"] = src_id
        cleaned["_tgt_ct"] = tgt_ct
        cleaned["_tgt_id"] = tgt_id
        return cleaned

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.source_content_type = self.cleaned_data["_src_ct"]
        obj.source_object_id = self.cleaned_data["_src_id"]
        obj.target_content_type = self.cleaned_data["_tgt_ct"]
        obj.target_object_id = self.cleaned_data["_tgt_id"]
        if commit:
            obj.save()
        return obj


class ContactForm(OrgBoundModelForm):
    class Meta:
        model = Contact
        fields = ["first_name", "last_name", "email", "phone", "title", "tags", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 6})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")


class RelationshipTypeForm(OrgBoundModelForm):
    class Meta:
        model = RelationshipType
        fields = ["name", "inverse_name", "symmetric"]


class TagForm(OrgBoundModelForm):
    global_tag = forms.BooleanField(required=False, help_text="Global tags are shared across organizations.")

    class Meta:
        model = Tag
        fields = ["name", "global_tag"]

    def __init__(self, *args, org=None, is_superuser=False, **kwargs):
        self.is_superuser = bool(is_superuser)
        super().__init__(*args, org=org, **kwargs)
        if not self.is_superuser:
            # Non-superusers can only create org-scoped tags within current org.
            self.fields.pop("global_tag", None)

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()

    def save(self, commit=True):
        obj = super().save(commit=False)
        if self.is_superuser and self.cleaned_data.get("global_tag"):
            obj.organization = None
        else:
            obj.organization = self.org
        if commit:
            obj.save()
        return obj


class CustomFieldForm(OrgBoundModelForm):
    class Meta:
        model = CustomField
        fields = ["content_type", "flexible_asset_type", "key", "name", "field_type", "required", "help_text", "sort_order"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        # Flexible asset type is only meaningful when content_type is FlexibleAsset.
        if self.org:
            self.fields["flexible_asset_type"].queryset = FlexibleAssetType.objects.filter(organization=self.org).order_by("name")
        self.fields["flexible_asset_type"].required = False
        self.fields["flexible_asset_type"].help_text = "Optional: scope this field to a specific flexible asset type."

    def clean(self):
        cleaned = super().clean()
        ct = cleaned.get("content_type")
        flex_type = cleaned.get("flexible_asset_type")
        try:
            flex_ct = ContentType.objects.get_for_model(FlexibleAsset)
        except Exception:
            flex_ct = None
        if flex_type and flex_ct and ct and int(ct.id) != int(flex_ct.id):
            self.add_error("flexible_asset_type", "Flexible asset type scoping can only be used when content type is FlexibleAsset.")
        if flex_type and self.org and int(flex_type.organization_id) != int(self.org.id):
            self.add_error("flexible_asset_type", "Flexible asset type must belong to the current organization.")
        return cleaned


class FlexibleAssetTypeForm(OrgBoundModelForm):
    class Meta:
        model = FlexibleAssetType
        fields = ["name", "description", "icon", "color", "sort_order", "archived"]
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()


class FlexibleAssetForm(OrgBoundModelForm):
    class Meta:
        model = FlexibleAsset
        fields = ["name", "tags", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 6})}

    def __init__(self, *args, org=None, asset_type=None, **kwargs):
        self.asset_type = asset_type
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()


class SavedViewForm(OrgBoundModelForm):
    class Meta:
        model = SavedView
        fields = ["name"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()


class DomainForm(OrgBoundModelForm):
    class Meta:
        model = Domain
        fields = ["name", "status", "registrar", "dns_provider", "expires_on", "auto_renew", "tags", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 6})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")


class SSLCertificateForm(OrgBoundModelForm):
    class Meta:
        model = SSLCertificate
        fields = [
            "common_name",
            "subject_alt_names",
            "issuer",
            "serial_number",
            "fingerprint_sha256",
            "not_before",
            "not_after",
            "domains",
            "tags",
            "notes",
        ]
        widgets = {
            "subject_alt_names": forms.Textarea(attrs={"rows": 3}),
            "notes": forms.Textarea(attrs={"rows": 6}),
        }

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")
            self.fields["domains"].queryset = Domain.objects.filter(organization=self.org).order_by("name")


class ChecklistForm(OrgBoundModelForm):
    class Meta:
        model = Checklist
        fields = ["name", "tags", "description"]
        widgets = {"description": forms.Textarea(attrs={"rows": 6})}

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["tags"].queryset = tags_queryset_for_org(self.org).order_by("name")


class ChecklistRunForm(OrgBoundModelForm):
    ref = forms.CharField(
        required=False,
        help_text='Optional link to an object. Format: "app_label.model:pk" (e.g. assets.asset:1)',
    )

    class Meta:
        model = ChecklistRun
        fields = ["name", "due_on", "assigned_to", "ref"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            User = get_user_model()
            member_ids = OrganizationMembership.objects.filter(organization=self.org).values_list("user_id", flat=True)
            self.fields["assigned_to"].queryset = User.objects.filter(id__in=member_ids).order_by("username")
            self.fields["assigned_to"].required = False

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()


class WorkflowRuleForm(OrgBoundModelForm):
    days = forms.IntegerField(required=False, min_value=1, max_value=3650, help_text="How many days ahead to warn.")
    grace_days = forms.IntegerField(required=False, min_value=0, max_value=3650, help_text="Grace period for overdue items (days).")

    class Meta:
        model = WorkflowRule
        fields = ["name", "enabled", "kind", "audience", "run_interval_minutes", "days", "grace_days"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        # Initial from params when editing.
        if self.instance and getattr(self.instance, "pk", None):
            try:
                d = (self.instance.params or {}).get("days")
                if d is not None and self.initial.get("days") is None:
                    self.initial["days"] = int(d)
            except Exception:
                pass
            try:
                g = (self.instance.params or {}).get("grace_days")
                if g is not None and self.initial.get("grace_days") is None:
                    self.initial["grace_days"] = int(g)
            except Exception:
                pass

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()

    def save(self, commit=True):
        obj = super().save(commit=False)
        params = dict(getattr(obj, "params", None) or {})
        kind = getattr(obj, "kind", None) or ""
        days = self.cleaned_data.get("days")
        grace_days = self.cleaned_data.get("grace_days")

        # Only persist params relevant to the selected rule type.
        if kind in [WorkflowRule.KIND_DOMAIN_EXPIRY, WorkflowRule.KIND_SSL_EXPIRY, WorkflowRule.KIND_PASSWORD_ROTATION_DUE]:
            if days is not None:
                params["days"] = int(days)
        else:
            params.pop("days", None)

        if kind == WorkflowRule.KIND_CHECKLIST_RUN_OVERDUE:
            if grace_days is not None:
                params["grace_days"] = int(grace_days)
        else:
            params.pop("grace_days", None)

        obj.params = params
        if commit:
            obj.save()
        return obj


class WebhookEndpointForm(OrgBoundModelForm):
    secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Optional secret used to sign payloads (HMAC-SHA256). Leave blank to keep unchanged.",
    )

    class Meta:
        model = WebhookEndpoint
        fields = ["name", "url", "secret", "verify_ssl", "enabled"]

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip() or "Webhook"

    def save(self, commit=True):
        obj = super().save(commit=False)
        secret = (self.cleaned_data.get("secret") or "").strip()
        if secret:
            obj.set_secret(secret)
        if commit:
            obj.save()
        return obj


class ProxmoxConnectionForm(OrgBoundModelForm):
    token_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Paste the Proxmox API token secret (stored encrypted). Leave blank to keep unchanged.",
    )

    class Meta:
        model = ProxmoxConnection
        fields = ["name", "base_url", "token_id", "token_secret", "verify_ssl", "enabled", "sync_interval_minutes"]

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip() or "Proxmox"

    def save(self, commit=True):
        obj = super().save(commit=False)
        secret = (self.cleaned_data.get("token_secret") or "").strip()
        if secret:
            obj.set_token_secret(secret)
        if commit:
            obj.save()
        return obj


class ChecklistScheduleForm(OrgBoundModelForm):
    class Meta:
        model = ChecklistSchedule
        fields = ["name", "enabled", "checklist", "every_days", "due_days", "assigned_to", "next_run_on"]

    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, org=org, **kwargs)
        if self.org:
            self.fields["checklist"].queryset = Checklist.objects.filter(organization=self.org, archived_at__isnull=True).order_by("name")
            User = get_user_model()
            member_ids = OrganizationMembership.objects.filter(organization=self.org).values_list("user_id", flat=True)
            self.fields["assigned_to"].queryset = User.objects.filter(id__in=member_ids).order_by("username")
            self.fields["assigned_to"].required = False

        self.fields["every_days"].min_value = 1
        self.fields["every_days"].help_text = "Create a run every N days."
        self.fields["due_days"].required = False
        self.fields["due_days"].help_text = "Optional: due date offset in days."

    def clean_name(self):
        return (self.cleaned_data.get("name") or "").strip()
