from __future__ import annotations

from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.filters import BaseFilterBackend, OrderingFilter, SearchFilter
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import (
    CustomField,
    CustomFieldValue,
    Location,
    Organization,
    OrganizationMembership,
    Relationship,
    RelationshipType,
    Tag,
    UserProfile,
)
from apps.docsapp.models import Document, DocumentFolder, DocumentTemplate
from apps.netapp.models import Domain, SSLCertificate
from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem, ChecklistSchedule
from apps.people.models import Contact
from apps.secretsapp.models import PasswordEntry, PasswordFolder
from apps.secretsapp.totp import TotpError, build_otpauth_url, generate_base32_secret, normalize_base32_secret
from apps.core.reauth import sign_reauth_token, verify_reauth_token
from apps.flexassets.models import FlexibleAsset, FlexibleAssetType
from apps.workflows.engine import run_rule
from apps.workflows.models import Notification, WebhookEndpoint, WorkflowRule

from .serializers import (
    AssetSerializer,
    ConfigurationItemSerializer,
    ContactSerializer,
    CustomFieldSerializer,
    CustomFieldValueSerializer,
    DomainSerializer,
    DocumentSerializer,
    DocumentFolderSerializer,
    DocumentTemplateSerializer,
    FlexibleAssetSerializer,
    FlexibleAssetTypeSerializer,
    ChecklistItemSerializer,
    ChecklistScheduleSerializer,
    ChecklistRunItemSerializer,
    ChecklistRunSerializer,
    ChecklistSerializer,
    LocationSerializer,
    OrganizationSerializer,
    PasswordEntrySerializer,
    PasswordFolderSerializer,
    RelationshipSerializer,
    RelationshipTypeSerializer,
    SSLCertificateSerializer,
    TagSerializer,
    NotificationSerializer,
    WebhookEndpointSerializer,
    WorkflowRuleSerializer,
    SearchResponseSerializer,
    MeSerializer,
    DefaultOrgRequestSerializer,
    ApiTokenStatusSerializer,
    ApiTokenRotateSerializer,
    ReauthRequestSerializer,
    ReauthResponseSerializer,
    _parse_ref,
)

from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema


class HomeGlueSearchFilter(SearchFilter):
    """
    DRF SearchFilter, but accept both ?q= and ?search= for convenience.
    """

    search_param = "q"

    def get_search_terms(self, request):
        raw = request.query_params.get("q")
        if raw is None or str(raw).strip() == "":
            raw = request.query_params.get("search", "")
        raw = (raw or "").replace("\x00", "")
        return [term for term in raw.split() if term]


class HomeGlueTagFilter(BaseFilterBackend):
    """
    Tag filtering for models with a `tags` M2M.

    Query params:
    - ?tag=<id|name>
    - ?tags=a,b,c (comma-separated; OR semantics)
    """

    def filter_queryset(self, request, queryset, view):
        model = getattr(queryset, "model", None)
        if model is None or not hasattr(model, "tags"):
            return queryset

        raw = request.query_params.get("tags") or request.query_params.get("tag") or ""
        raw = (raw or "").strip()
        if not raw:
            return queryset

        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            return queryset

        q = Q()
        for p in parts:
            if p.isdigit():
                q |= Q(tags__id=int(p))
            else:
                q |= Q(tags__name__iexact=p)
        return queryset.filter(q).distinct()


def _member_org_ids_for_user(user) -> set[int]:
    if not user or not user.is_authenticated:
        return set()
    return set(OrganizationMembership.objects.filter(user=user).values_list("organization_id", flat=True))


def _profile_default_org_id_for_user(user) -> int | None:
    if not user or not user.is_authenticated:
        return None
    try:
        profile = user.profile
    except UserProfile.DoesNotExist:
        return None
    return int(profile.default_organization_id) if profile.default_organization_id else None


def _user_is_org_admin(user, org_id: int | None) -> bool:
    if not user or not user.is_authenticated:
        return False
    if getattr(user, "is_superuser", False):
        return True
    if not org_id:
        return False
    return OrganizationMembership.objects.filter(
        user=user,
        organization_id=org_id,
        role__in=[OrganizationMembership.ROLE_OWNER, OrganizationMembership.ROLE_ADMIN],
    ).exists()


def _ensure_user_ids_in_org(*, org_id: int, user_ids: list[int]) -> None:
    """
    Validate that all user_ids are members of the org (used for shared ACL lists).
    """

    if not user_ids:
        return
    have = set(
        OrganizationMembership.objects.filter(organization_id=int(org_id), user_id__in=[int(x) for x in user_ids]).values_list(
            "user_id", flat=True
        )
    )
    want = set([int(x) for x in user_ids])
    missing = sorted(list(want - have))
    if missing:
        raise ValidationError({"allowed_users": "All allowed_users must be members of the selected organization."})


def _reauth_ttl_seconds() -> int:
    try:
        return int(getattr(settings, "HOMEGLUE_REAUTH_TTL_SECONDS", 900) or 900)
    except Exception:
        return 900


def _require_reauth(request) -> None:
    user = request.user
    if not user or not user.is_authenticated:
        raise PermissionDenied("Not authenticated.")
    tok = request.headers.get("X-HomeGlue-Reauth", "") or ""
    if not verify_reauth_token(token=tok, user_id=int(user.id), ttl_seconds=_reauth_ttl_seconds()):
        raise PermissionDenied("Re-auth required. POST /api/me/reauth/ and pass X-HomeGlue-Reauth.")


def _requested_org_id_raw(request, *, kwargs: dict | None = None):
    """
    Resolve the org id *input* (string-ish) from the request.

    URL path org_id (if present) wins, since it represents "entered org" navigation.
    """
    kwargs = kwargs or {}
    if kwargs.get("org_id") is not None:
        return kwargs.get("org_id")

    org_id = request.query_params.get("org")
    if org_id:
        return org_id
    org_id = request.headers.get("X-HomeGlue-Org")
    if org_id:
        return org_id
    return request.data.get("organization")


def resolve_org_id(request, *, kwargs: dict | None = None, required: bool) -> int | None:
    """
    Resolve the current org for this request.

    For non-superusers, the resolved org must be within the user's memberships.
    """
    user = request.user
    raw = _requested_org_id_raw(request, kwargs=kwargs)

    if user and user.is_superuser:
        return int(raw) if raw else None

    member_org_ids = _member_org_ids_for_user(user)

    if raw:
        org_id = int(raw)
        if org_id not in member_org_ids:
            raise PermissionDenied("You do not have access to this organization.")
        return org_id

    default_org_id = _profile_default_org_id_for_user(user)
    if default_org_id and default_org_id in member_org_ids:
        return default_org_id

    if required:
        raise ValidationError(
            {
                "org": "Missing organization context. Enter an org (/api/orgs/<id>/...) or provide ?org=<id> / "
                "X-HomeGlue-Org, or set a default via /api/me/default-org/."
            }
        )
    return None


class OrgScopedViewSet(viewsets.ModelViewSet):
    """
    Org scoping:
    - superusers can see all / write all
    - non-superusers can only access orgs they are members of
    - org can be selected via:
      - `?org=<id>`
      - `X-HomeGlue-Org: <id>`
      - `organization` in request payload (create/update)
      - user profile default org
    """

    org_field = "organization"
    filter_backends = [HomeGlueSearchFilter, HomeGlueTagFilter, OrderingFilter]
    ordering_fields = "__all__"

    def _resolve_org_id(self, *, required: bool) -> int | None:
        return resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=required)

    def _require_org_admin(self) -> int:
        org_id = self._resolve_org_id(required=True)
        if not _user_is_org_admin(self.request.user, org_id):
            raise PermissionDenied("Org admin role required.")
        return int(org_id)

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user.is_superuser:
            org_id = self._resolve_org_id(required=False)
            if org_id:
                qs = qs.filter(**{f"{self.org_field}_id": org_id})
            return self._filter_archived(qs)
        # Non-superusers must always be "in" an org context for org-scoped resources.
        org_id = self._resolve_org_id(required=True)
        if not org_id:
            return qs.none()
        qs = qs.filter(**{f"{self.org_field}_id": org_id})
        return self._filter_archived(qs)

    def _filter_archived(self, qs):
        """
        Default: hide archived objects (archived_at IS NULL) for models supporting soft-delete.

        Query param:
        - `?archived=1|true|yes|on|include|all`: include archived
        - `?archived=only`: only archived
        """

        if not hasattr(qs.model, "archived_at"):
            return qs
        raw = (self.request.query_params.get("archived") or "").strip().lower()
        if raw in {"1", "true", "yes", "on", "include", "all"}:
            return qs
        if raw in {"only"}:
            return qs.filter(archived_at__isnull=False)
        return qs.filter(archived_at__isnull=True)

    def perform_create(self, serializer):
        user = self.request.user
        if user.is_superuser:
            org_id = self._resolve_org_id(required=False)
            if org_id:
                serializer.save(**{f"{self.org_field}_id": org_id})
            else:
                serializer.save()
            return
        org_id = self._resolve_org_id(required=True)
        serializer.save(**{f"{self.org_field}_id": org_id})

    def perform_destroy(self, instance):
        # Soft-delete (archive) for models supporting it.
        if hasattr(instance, "archived_at"):
            org_id = getattr(instance, f"{self.org_field}_id", None)
            if not _user_is_org_admin(self.request.user, int(org_id) if org_id else None):
                raise PermissionDenied("Org admin role required.")
            if getattr(instance, "archived_at", None) is None:
                instance.archived_at = timezone.now()
                instance.save(update_fields=["archived_at"])
            return
        return instance.delete()

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None, org_id=None, **kwargs):
        """
        Restore (un-archive) a previously archived object.
        """

        # Enforce org context even for superusers to avoid accidental cross-org restores.
        org_id_int = self._resolve_org_id(required=True)
        if not _user_is_org_admin(request.user, int(org_id_int) if org_id_int else None):
            raise PermissionDenied("Org admin role required.")

        model_cls = self.get_queryset().model
        if not hasattr(model_cls, "archived_at"):
            raise PermissionDenied("This object type cannot be restored.")

        obj = model_cls.objects.filter(**{f"{self.org_field}_id": org_id_int, "pk": pk}).first()
        if obj is None:
            raise PermissionDenied("Object not found.")
        if getattr(obj, "archived_at", None) is not None:
            obj.archived_at = None
            obj.save(update_fields=["archived_at"])
        return Response({"ok": True})
    def get_object(self):
        obj = super().get_object()
        user = self.request.user
        if user.is_superuser:
            org_id = self._resolve_org_id(required=False)
            if org_id:
                obj_org_id = getattr(obj, f"{self.org_field}_id", None)
                if obj_org_id is not None and int(obj_org_id) != int(org_id):
                    raise PermissionDenied("Object does not belong to the selected organization.")
            return obj
        org_id = getattr(obj, f"{self.org_field}_id", None)
        req_org_id = self._resolve_org_id(required=True)
        if int(req_org_id) != int(org_id):
            raise PermissionDenied("Object does not belong to the selected organization.")
        return obj


class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all().order_by("name")
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user and user.is_superuser:
            return qs
        if not user or not user.is_authenticated:
            return qs.none()
        org_ids = OrganizationMembership.objects.filter(user=user).values_list("organization_id", flat=True)
        return qs.filter(id__in=org_ids)

    def perform_create(self, serializer):
        # Keep org creation restricted for now.
        user = self.request.user
        if not (user and user.is_superuser):
            raise PermissionDenied("Only superusers can create organizations.")
        return super().perform_create(serializer)


class LocationViewSet(OrgScopedViewSet):
    queryset = Location.objects.select_related("organization").all().order_by("name")
    serializer_class = LocationSerializer
    search_fields = ["name", "address"]


class TagViewSet(viewsets.ModelViewSet):
    queryset = Tag.objects.select_related("organization").all().order_by("name")
    serializer_class = TagSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user and user.is_superuser:
            org_id = resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=False)
            if org_id:
                return qs.filter(Q(organization__isnull=True) | Q(organization_id=org_id))
            return qs

        # Tags are not org-scoped resources themselves, but viewing/creating tags
        # is always in the context of a selected org:
        # return (global tags) + (tags scoped to selected org).
        org_id = resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=True)
        return qs.filter(Q(organization__isnull=True) | Q(organization_id=org_id))

    def perform_create(self, serializer):
        user = self.request.user
        if user and user.is_superuser:
            org_id = resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=False)
            if org_id is not None:
                serializer.save(organization_id=org_id)
            else:
                serializer.save()
            return
        org_id = resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=True)

        # Non-superusers can only create org-scoped tags for the selected org.
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        user = self.request.user
        if user and user.is_superuser:
            return serializer.save()

        # Non-superusers cannot modify global tags.
        if serializer.instance and serializer.instance.organization_id is None:
            raise PermissionDenied("Only superusers can modify global tags.")

        org_id = resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=True)
        if serializer.instance and serializer.instance.organization_id and int(serializer.instance.organization_id) != int(org_id):
            raise PermissionDenied("Tag does not belong to the selected organization.")

        # Also prevent switching a tag to global via payload.
        if "organization" in serializer.validated_data and serializer.validated_data.get("organization") is None:
            raise PermissionDenied("Only superusers can create/modify global tags.")

        return serializer.save(organization_id=org_id)

    def perform_destroy(self, instance):
        user = self.request.user
        if user and user.is_superuser:
            return instance.delete()

        if instance.organization_id is None:
            raise PermissionDenied("Only superusers can delete global tags.")
        org_id = resolve_org_id(self.request, kwargs=getattr(self, "kwargs", None), required=True)
        if int(instance.organization_id) != int(org_id):
            raise PermissionDenied("Tag does not belong to the selected organization.")
        return instance.delete()


class ContactViewSet(OrgScopedViewSet):
    queryset = Contact.objects.select_related("organization").all().order_by("last_name", "first_name")
    serializer_class = ContactSerializer
    search_fields = ["first_name", "last_name", "email", "phone", "title", "notes"]


class AssetViewSet(OrgScopedViewSet):
    queryset = Asset.objects.select_related("organization", "location").all().order_by("name")
    serializer_class = AssetSerializer
    search_fields = ["name", "asset_type", "manufacturer", "model", "serial_number", "notes"]


class ConfigurationItemViewSet(OrgScopedViewSet):
    queryset = ConfigurationItem.objects.select_related("organization").all().order_by("name")
    serializer_class = ConfigurationItemSerializer
    search_fields = ["name", "ci_type", "hostname", "primary_ip", "operating_system", "notes"]


class DocumentTemplateViewSet(OrgScopedViewSet):
    queryset = DocumentTemplate.objects.select_related("organization").all().order_by("name")
    serializer_class = DocumentTemplateSerializer
    search_fields = ["name", "body"]


class DocumentFolderViewSet(OrgScopedViewSet):
    queryset = DocumentFolder.objects.select_related("organization", "parent").all().order_by("parent_id", "name")
    serializer_class = DocumentFolderSerializer
    search_fields = ["name"]

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        parent = serializer.validated_data.get("parent")
        if parent is not None and int(parent.organization_id) != int(org_id):
            raise ValidationError({"parent": "Parent folder must belong to the selected organization."})
        super().perform_create(serializer)

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        parent = serializer.validated_data.get("parent")
        if parent is not None and int(parent.organization_id) != int(org_id):
            raise ValidationError({"parent": "Parent folder must belong to the selected organization."})
        super().perform_update(serializer)


class DocumentViewSet(OrgScopedViewSet):
    queryset = Document.objects.select_related("organization", "template", "flagged_by").all().order_by("-updated_at")
    serializer_class = DocumentSerializer
    search_fields = ["title", "body"]

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        org_id = self._resolve_org_id(required=True)
        if user and (user.is_superuser or _user_is_org_admin(user, org_id)):
            return self._filter_flagged(qs)
        if not user or not user.is_authenticated:
            return qs.none()
        qs = (
            qs.filter(
                Q(visibility=Document.VIS_ORG)
                | (Q(visibility=Document.VIS_ADMINS) & Q(created_by=user))
                | (Q(visibility=Document.VIS_PRIVATE) & Q(created_by=user))
                | (Q(visibility=Document.VIS_SHARED) & (Q(created_by=user) | Q(allowed_users=user)))
            )
            .distinct()
        )
        return self._filter_flagged(qs)

    def _filter_flagged(self, qs):
        raw = (self.request.query_params.get("flagged") or "").strip().lower()
        if raw in {"1", "true", "yes", "on", "only"}:
            return qs.filter(flagged_at__isnull=False)
        return qs

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        folder = serializer.validated_data.get("folder")
        if folder is not None and int(folder.organization_id) != int(org_id):
            raise ValidationError({"folder": "Folder must belong to the selected organization."})
        allowed = serializer.validated_data.get("allowed_users") or []
        vis = serializer.validated_data.get("visibility") or Document.VIS_ORG
        if vis != Document.VIS_SHARED and allowed:
            raise ValidationError({"allowed_users": "allowed_users is only valid when visibility=shared."})
        _ensure_user_ids_in_org(org_id=int(org_id), user_ids=[int(u.id) for u in allowed])
        super().perform_create(serializer)
        # created_by must reflect the caller, not the payload.
        obj = serializer.instance
        if obj and getattr(obj, "created_by_id", None) is None:
            obj.created_by = self.request.user
            obj.save(update_fields=["created_by"])

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        folder = serializer.validated_data.get("folder")
        if folder is not None and int(folder.organization_id) != int(org_id):
            raise ValidationError({"folder": "Folder must belong to the selected organization."})
        allowed = serializer.validated_data.get("allowed_users")
        vis = serializer.validated_data.get("visibility")
        if allowed is not None:
            if vis is None:
                vis = getattr(serializer.instance, "visibility", None)
            if vis != Document.VIS_SHARED and allowed:
                raise ValidationError({"allowed_users": "allowed_users is only valid when visibility=shared."})
            _ensure_user_ids_in_org(org_id=int(org_id), user_ids=[int(u.id) for u in allowed])
        super().perform_update(serializer)
        obj = serializer.instance
        # Maintain flagged_by in lock-step with flagged_at changes.
        if obj and "flagged_at" in getattr(serializer, "validated_data", {}):
            if obj.flagged_at is not None:
                obj.flagged_by = self.request.user
            else:
                obj.flagged_by = None
            obj.save(update_fields=["flagged_by"])
        if obj and getattr(obj, "visibility", None) != Document.VIS_SHARED:
            obj.allowed_users.clear()
        return


class PasswordEntryViewSet(OrgScopedViewSet):
    queryset = PasswordEntry.objects.select_related("organization", "folder").all().order_by("name")
    serializer_class = PasswordEntrySerializer
    search_fields = ["name", "username", "url", "notes"]

    @action(detail=True, methods=["post"])
    def reveal(self, request, pk=None, org_id=None, **kwargs):
        _require_reauth(request)
        obj = self.get_object()
        return Response({"password": obj.get_password()})

    def _update_totp(
        self,
        *,
        obj: PasswordEntry,
        secret_b32: str | None,
        digits: int | None = None,
        period: int | None = None,
        algorithm: str | None = None,
    ) -> dict:
        if secret_b32 is None:
            secret_b32 = generate_base32_secret()
        try:
            secret_norm = normalize_base32_secret(secret_b32)
        except TotpError as e:
            raise ValidationError({"secret": str(e)})

        algo = (algorithm or "SHA1").upper()
        if algo not in ["SHA1", "SHA256", "SHA512"]:
            raise ValidationError({"algorithm": "algorithm must be one of: SHA1, SHA256, SHA512"})

        try:
            d = int(digits) if digits is not None else 6
            p = int(period) if period is not None else 30
        except Exception:
            raise ValidationError({"detail": "digits/period must be integers"})
        if d < 6 or d > 10:
            raise ValidationError({"digits": "digits must be between 6 and 10"})
        if p < 15 or p > 300:
            raise ValidationError({"period": "period must be between 15 and 300 seconds"})

        obj.set_totp_secret(secret_norm)
        obj.totp_digits = d
        obj.totp_period = p
        obj.totp_algorithm = algo
        obj.save(update_fields=["totp_secret_ciphertext", "totp_digits", "totp_period", "totp_algorithm", "updated_at"])

        acct = obj.username or obj.name
        uri = build_otpauth_url(
            issuer="HomeGlue",
            account_name=f"{obj.organization.name} / {acct}",
            secret_b32=secret_norm,
            digits=d,
            period=p,
            algorithm=algo,
        )
        return {"secret": secret_norm, "otpauth_url": uri, "digits": d, "period": p, "algorithm": algo}

    @action(detail=True, methods=["post"], url_path="totp-enable")
    def totp_enable(self, request, pk=None, org_id=None, **kwargs):
        _require_reauth(request)
        obj = self.get_object()
        if obj.has_totp():
            raise ValidationError({"detail": "TOTP is already enabled. Use totp-rotate to rotate it."})
        payload = self._update_totp(
            obj=obj,
            secret_b32=request.data.get("secret"),
            digits=request.data.get("digits"),
            period=request.data.get("period"),
            algorithm=request.data.get("algorithm"),
        )
        return Response(payload, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="totp-rotate")
    def totp_rotate(self, request, pk=None, org_id=None, **kwargs):
        _require_reauth(request)
        obj = self.get_object()
        payload = self._update_totp(
            obj=obj,
            secret_b32=request.data.get("secret"),
            digits=request.data.get("digits"),
            period=request.data.get("period"),
            algorithm=request.data.get("algorithm"),
        )
        return Response(payload, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="totp-disable")
    def totp_disable(self, request, pk=None, org_id=None, **kwargs):
        _require_reauth(request)
        obj = self.get_object()
        if obj.has_totp():
            obj.clear_totp()
            obj.save(update_fields=["totp_secret_ciphertext", "updated_at"])
        return Response({"detail": "disabled"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"], url_path="totp-code")
    def totp_code(self, request, pk=None, org_id=None, **kwargs):
        _require_reauth(request)
        obj = self.get_object()
        if not obj.has_totp():
            raise ValidationError({"detail": "TOTP is not enabled."})
        try:
            code, remaining = obj.get_totp_code()
        except TotpError as e:
            raise ValidationError({"detail": str(e)})
        return Response(
            {
                "code": code,
                "remaining": int(remaining),
                "period": int(obj.totp_period or 30),
                "digits": int(obj.totp_digits or 6),
                "algorithm": (obj.totp_algorithm or "SHA1"),
            },
            status=status.HTTP_200_OK,
        )

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        org_id = self._resolve_org_id(required=True)
        if user and (user.is_superuser or _user_is_org_admin(user, org_id)):
            return qs
        if not user or not user.is_authenticated:
            return qs.none()
        return (
            qs.filter(
                Q(visibility=PasswordEntry.VIS_ORG)
                | (Q(visibility=PasswordEntry.VIS_ADMINS) & Q(created_by=user))
                | (Q(visibility=PasswordEntry.VIS_PRIVATE) & Q(created_by=user))
                | (Q(visibility=PasswordEntry.VIS_SHARED) & (Q(created_by=user) | Q(allowed_users=user)))
            )
            .distinct()
        )

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        folder = serializer.validated_data.get("folder")
        if folder is not None and int(folder.organization_id) != int(org_id):
            raise ValidationError({"folder": "Folder must belong to the selected organization."})
        allowed = serializer.validated_data.get("allowed_users") or []
        vis = serializer.validated_data.get("visibility") or PasswordEntry.VIS_ADMINS
        if vis != PasswordEntry.VIS_SHARED and allowed:
            raise ValidationError({"allowed_users": "allowed_users is only valid when visibility=shared."})
        _ensure_user_ids_in_org(org_id=int(org_id), user_ids=[int(u.id) for u in allowed])
        super().perform_create(serializer)
        obj = serializer.instance
        if obj and getattr(obj, "created_by_id", None) is None:
            obj.created_by = self.request.user
            obj.save(update_fields=["created_by"])

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        folder = serializer.validated_data.get("folder")
        if folder is not None and int(folder.organization_id) != int(org_id):
            raise ValidationError({"folder": "Folder must belong to the selected organization."})
        allowed = serializer.validated_data.get("allowed_users")
        vis = serializer.validated_data.get("visibility")
        if allowed is not None:
            if vis is None:
                vis = getattr(serializer.instance, "visibility", None)
            if vis != PasswordEntry.VIS_SHARED and allowed:
                raise ValidationError({"allowed_users": "allowed_users is only valid when visibility=shared."})
            _ensure_user_ids_in_org(org_id=int(org_id), user_ids=[int(u.id) for u in allowed])
        super().perform_update(serializer)
        obj = serializer.instance
        if obj and getattr(obj, "visibility", None) != PasswordEntry.VIS_SHARED:
            obj.allowed_users.clear()
        return


class PasswordFolderViewSet(OrgScopedViewSet):
    queryset = PasswordFolder.objects.select_related("organization", "parent").all().order_by("parent_id", "name")
    serializer_class = PasswordFolderSerializer
    search_fields = ["name"]


class DomainViewSet(OrgScopedViewSet):
    queryset = Domain.objects.select_related("organization").prefetch_related("tags").all().order_by("name")
    serializer_class = DomainSerializer
    search_fields = ["name", "registrar", "dns_provider", "notes"]


class SSLCertificateViewSet(OrgScopedViewSet):
    queryset = (
        SSLCertificate.objects.select_related("organization")
        .prefetch_related("domains", "tags")
        .all()
        .order_by("not_after", "common_name")
    )
    serializer_class = SSLCertificateSerializer
    search_fields = ["common_name", "issuer", "serial_number", "fingerprint_sha256", "subject_alt_names", "notes"]


class ChecklistViewSet(OrgScopedViewSet):
    queryset = Checklist.objects.select_related("organization").prefetch_related("tags").all().order_by("-updated_at", "name")
    serializer_class = ChecklistSerializer
    search_fields = ["name", "description"]


class ChecklistItemViewSet(OrgScopedViewSet):
    queryset = ChecklistItem.objects.select_related("organization", "checklist").all().order_by("checklist_id", "sort_order", "id")
    serializer_class = ChecklistItemSerializer

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        chk = serializer.validated_data.get("checklist")
        if chk and int(chk.organization_id) != int(org_id):
            raise ValidationError({"checklist": "Checklist must belong to the selected organization."})
        super().perform_create(serializer)

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        chk = serializer.validated_data.get("checklist") or getattr(serializer.instance, "checklist", None)
        if chk and int(chk.organization_id) != int(org_id):
            raise ValidationError({"checklist": "Checklist must belong to the selected organization."})
        super().perform_update(serializer)


class ChecklistScheduleViewSet(OrgScopedViewSet):
    queryset = (
        ChecklistSchedule.objects.select_related("organization", "checklist", "assigned_to")
        .all()
        .order_by("-enabled", "next_run_on", "name", "id")
    )
    serializer_class = ChecklistScheduleSerializer

    def create(self, request, *args, **kwargs):
        """
        Inject organization into the payload so model-level uniqueness validators can run without requiring clients
        to send it explicitly.
        """

        org_id = self._resolve_org_id(required=True)
        data = request.data.copy()
        if data.get("organization") in (None, "", 0) and data.get("organization_id") in (None, "", 0):
            data["organization"] = int(org_id)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        org_id = self._require_org_admin()
        chk = serializer.validated_data.get("checklist")
        if chk is not None and int(chk.organization_id) != int(org_id):
            raise ValidationError({"checklist": "Checklist must belong to the selected organization."})
        assigned_to = serializer.validated_data.get("assigned_to")
        if assigned_to is not None:
            ok = OrganizationMembership.objects.filter(organization_id=int(org_id), user_id=int(assigned_to.id)).exists()
            if not ok:
                raise ValidationError({"assigned_to": "assigned_to must be a member of the selected organization."})
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        self._require_org_admin()
        org_id = self._resolve_org_id(required=True)
        chk = serializer.validated_data.get("checklist") or getattr(serializer.instance, "checklist", None)
        if chk is not None and int(chk.organization_id) != int(org_id):
            raise ValidationError({"checklist": "Checklist must belong to the selected organization."})
        assigned_to = serializer.validated_data.get("assigned_to")
        if assigned_to is not None:
            ok = OrganizationMembership.objects.filter(organization_id=int(org_id), user_id=int(assigned_to.id)).exists()
            if not ok:
                raise ValidationError({"assigned_to": "assigned_to must be a member of the selected organization."})
        serializer.save()


class ChecklistRunViewSet(OrgScopedViewSet):
    queryset = (
        ChecklistRun.objects.select_related("organization", "checklist", "assigned_to", "created_by", "content_type")
        .all()
        .order_by("-updated_at", "-id")
    )
    serializer_class = ChecklistRunSerializer
    search_fields = ["name"]

    def get_queryset(self):
        qs = super().get_queryset()
        raw = (self.request.query_params.get("status") or "").strip().lower()
        if raw in {"open", "done", "canceled"}:
            qs = qs.filter(status=raw)
        return qs

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        chk = serializer.validated_data.get("checklist")
        if chk and int(chk.organization_id) != int(org_id):
            raise ValidationError({"checklist": "Checklist must belong to the selected organization."})
        ref = (serializer.validated_data.pop("ref", "") or "").strip()
        super().perform_create(serializer)
        obj = serializer.instance
        if obj and getattr(obj, "created_by_id", None) is None:
            obj.created_by = self.request.user
            obj.save(update_fields=["created_by"])
        if ref and obj:
            try:
                ct, oid, _ = _parse_ref(ref)
                obj.content_type = ct
                obj.object_id = oid
                obj.save(update_fields=["content_type", "object_id"])
            except Exception:
                pass


class ChecklistRunItemViewSet(OrgScopedViewSet):
    queryset = (
        ChecklistRunItem.objects.select_related("organization", "run", "checklist_item", "done_by")
        .all()
        .order_by("run_id", "sort_order", "id")
    )
    serializer_class = ChecklistRunItemSerializer

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        run = serializer.validated_data.get("run")
        if run and int(run.organization_id) != int(org_id):
            raise ValidationError({"run": "Run must belong to the selected organization."})
        super().perform_create(serializer)

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        run = serializer.validated_data.get("run") or getattr(serializer.instance, "run", None)
        if run and int(run.organization_id) != int(org_id):
            raise ValidationError({"run": "Run must belong to the selected organization."})
        super().perform_update(serializer)
        obj = serializer.instance
        if obj and "is_done" in getattr(serializer, "validated_data", {}):
            if obj.is_done:
                if obj.done_by_id is None:
                    obj.done_by = self.request.user
                if obj.done_at is None:
                    obj.done_at = timezone.now()
            else:
                obj.done_by = None
                obj.done_at = None
            obj.save(update_fields=["done_by", "done_at"])


class FlexibleAssetTypeViewSet(OrgScopedViewSet):
    queryset = FlexibleAssetType.objects.select_related("organization").all().order_by("archived", "sort_order", "name")
    serializer_class = FlexibleAssetTypeSerializer
    search_fields = ["name", "description"]

    def perform_create(self, serializer):
        org_id = self._require_org_admin()
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        self._require_org_admin()
        serializer.save()

    def perform_destroy(self, instance):
        self._require_org_admin()
        instance.delete()


class FlexibleAssetViewSet(OrgScopedViewSet):
    queryset = FlexibleAsset.objects.select_related("organization", "asset_type").prefetch_related("tags").all().order_by("name")
    serializer_class = FlexibleAssetSerializer
    search_fields = ["name", "notes"]

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        at = serializer.validated_data.get("asset_type")
        if at is not None and int(at.organization_id) != int(org_id):
            raise ValidationError({"asset_type": "Flexible asset type must belong to the selected organization."})
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        at = serializer.validated_data.get("asset_type") or getattr(serializer.instance, "asset_type", None)
        if at is not None and int(at.organization_id) != int(org_id):
            raise ValidationError({"asset_type": "Flexible asset type must belong to the selected organization."})
        serializer.save()


class RelationshipTypeViewSet(OrgScopedViewSet):
    queryset = RelationshipType.objects.select_related("organization").all().order_by("name")
    serializer_class = RelationshipTypeSerializer

    def perform_create(self, serializer):
        org_id = self._require_org_admin()
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        self._require_org_admin()
        serializer.save()

    def perform_destroy(self, instance):
        self._require_org_admin()
        instance.delete()


class RelationshipViewSet(OrgScopedViewSet):
    queryset = (
        Relationship.objects.select_related(
            "organization",
            "relationship_type",
            "source_content_type",
            "target_content_type",
            "created_by",
        )
        .all()
        .order_by("-created_at")
    )
    serializer_class = RelationshipSerializer

    def _validate_related_objects_in_org(self, *, org_id: int, serializer: RelationshipSerializer) -> None:
        """
        Ensure the relationship endpoints don't allow cross-org references.
        """

        v = serializer.validated_data
        src_ct = v.get("source_content_type")
        src_id = v.get("source_object_id")
        tgt_ct = v.get("target_content_type")
        tgt_id = v.get("target_object_id")

        for side, ct, obj_id in [("source_ref", src_ct, src_id), ("target_ref", tgt_ct, tgt_id)]:
            if not ct or not obj_id:
                continue
            model_cls = ct.model_class()
            if model_cls is None:
                raise ValidationError({side: "Invalid content type."})
            try:
                obj = model_cls.objects.get(pk=obj_id)
            except model_cls.DoesNotExist:
                raise ValidationError({side: "Object not found."})
            obj_org_id = getattr(obj, "organization_id", None)
            if obj_org_id is not None and int(obj_org_id) != int(org_id):
                raise ValidationError({side: "Referenced object must belong to the selected organization."})

    def perform_create(self, serializer):
        user = self.request.user
        created_by = user if user and user.is_authenticated else None
        org_id = self._resolve_org_id(required=True)
        rel_type = serializer.validated_data.get("relationship_type")
        if rel_type is not None and int(rel_type.organization_id) != int(org_id):
            raise ValidationError({"relationship_type": "Relationship type organization must match selected organization."})
        self._validate_related_objects_in_org(org_id=org_id, serializer=serializer)
        serializer.save(organization_id=org_id, created_by=created_by)

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        rel_type = serializer.validated_data.get("relationship_type") or getattr(serializer.instance, "relationship_type", None)
        if rel_type is not None and int(rel_type.organization_id) != int(org_id):
            raise ValidationError({"relationship_type": "Relationship type organization must match selected organization."})
        self._validate_related_objects_in_org(org_id=org_id, serializer=serializer)
        serializer.save()


class CustomFieldViewSet(OrgScopedViewSet):
    queryset = CustomField.objects.select_related("organization", "content_type").all().order_by("sort_order", "name")
    serializer_class = CustomFieldSerializer

    def _validate_flexible_asset_scope(self, *, org_id: int, serializer: CustomFieldSerializer) -> None:
        flex_type = serializer.validated_data.get("flexible_asset_type") or getattr(serializer.instance, "flexible_asset_type", None)
        if flex_type is None:
            return
        if int(flex_type.organization_id) != int(org_id):
            raise ValidationError({"flexible_asset_type": "Flexible asset type must belong to the selected organization."})
        ct = serializer.validated_data.get("content_type") or getattr(serializer.instance, "content_type", None)
        if ct is None:
            return
        from django.contrib.contenttypes.models import ContentType

        flex_ct = ContentType.objects.get_for_model(FlexibleAsset)
        if int(ct.id) != int(flex_ct.id):
            raise ValidationError({"flexible_asset_type": "Flexible asset type scoping can only be used with FlexibleAsset content type."})

    def perform_create(self, serializer):
        org_id = self._require_org_admin()
        self._validate_flexible_asset_scope(org_id=org_id, serializer=serializer)
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        self._require_org_admin()
        org_id = self._resolve_org_id(required=True)
        self._validate_flexible_asset_scope(org_id=int(org_id), serializer=serializer)
        serializer.save()

    def perform_destroy(self, instance):
        self._require_org_admin()
        instance.delete()


class CustomFieldValueViewSet(OrgScopedViewSet):
    queryset = (
        CustomFieldValue.objects.select_related("organization", "field", "content_type")
        .all()
        .order_by("-updated_at")
    )
    serializer_class = CustomFieldValueSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Optional filtering by object reference for convenience.
        ref = (self.request.query_params.get("ref") or "").strip()
        if not ref:
            return qs
        try:
            # Reuse Relationship parsing helper.
            from .serializers import _parse_ref
        except Exception:
            return qs
        ct, obj_id, _ = _parse_ref(ref)
        return qs.filter(content_type=ct, object_id=str(obj_id))

    def perform_create(self, serializer):
        org_id = self._resolve_org_id(required=True)
        field: CustomField | None = serializer.validated_data.get("field")
        ct = serializer.validated_data.get("content_type")
        obj_id = serializer.validated_data.get("object_id")

        if field is None or ct is None or obj_id is None:
            raise ValidationError("Missing field or object reference.")
        if int(field.organization_id) != int(org_id):
            raise ValidationError({"field": "Field must belong to the selected organization."})
        if int(field.content_type_id) != int(ct.id):
            raise ValidationError({"ref": "Field applies to a different object type."})

        # If the referenced object is org-scoped, enforce same org.
        model_cls = ct.model_class()
        if model_cls is not None:
            meta = getattr(model_cls, "_meta", None)
            fields = getattr(meta, "fields", []) if meta else []
            has_org_field = any(getattr(f, "name", None) == "organization" for f in fields)
            if has_org_field:
                try:
                    obj = model_cls.objects.get(pk=obj_id)
                except model_cls.DoesNotExist:
                    raise ValidationError({"ref": "Object not found."})
                if int(getattr(obj, "organization_id")) != int(org_id):
                    raise ValidationError({"ref": "Object must belong to the selected organization."})

        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        org_id = self._resolve_org_id(required=True)
        field: CustomField | None = serializer.validated_data.get("field") or getattr(serializer.instance, "field", None)
        ct = serializer.validated_data.get("content_type") or getattr(serializer.instance, "content_type", None)
        obj_id = serializer.validated_data.get("object_id") or getattr(serializer.instance, "object_id", None)

        if field is None or ct is None or obj_id is None:
            raise ValidationError("Missing field or object reference.")
        if int(field.organization_id) != int(org_id):
            raise ValidationError({"field": "Field must belong to the selected organization."})
        if int(field.content_type_id) != int(ct.id):
            raise ValidationError({"ref": "Field applies to a different object type."})

        model_cls = ct.model_class()
        if model_cls is not None:
            meta = getattr(model_cls, "_meta", None)
            fields = getattr(meta, "fields", []) if meta else []
            has_org_field = any(getattr(f, "name", None) == "organization" for f in fields)
            if has_org_field:
                try:
                    obj = model_cls.objects.get(pk=obj_id)
                except model_cls.DoesNotExist:
                    raise ValidationError({"ref": "Object not found."})
                if int(getattr(obj, "organization_id")) != int(org_id):
                    raise ValidationError({"ref": "Object must belong to the selected organization."})
        serializer.save()


class WorkflowRuleViewSet(OrgScopedViewSet):
    queryset = WorkflowRule.objects.select_related("organization").all().order_by("kind", "name", "id")
    serializer_class = WorkflowRuleSerializer
    search_fields = ["name", "kind", "audience"]

    def get_queryset(self):
        # Always require explicit org context (even for superusers) to avoid cross-org combined views.
        org_id = self._resolve_org_id(required=True)
        return super().get_queryset().filter(organization_id=int(org_id))

    def perform_create(self, serializer):
        org_id = self._require_org_admin()
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        self._require_org_admin()
        serializer.save()

    def perform_destroy(self, instance):
        self._require_org_admin()
        instance.delete()

    @action(detail=True, methods=["post"])
    def run_now(self, request, pk=None, org_id=None, **kwargs):
        self._require_org_admin()
        rule = self.get_object()
        res = run_rule(rule)
        if not res.ok:
            raise ValidationError({"detail": str(res.error or "rule did not run")})
        rule.refresh_from_db()
        return Response(
            {
                "ok": True,
                "notifications_created": int(res.notifications_created or 0),
                "last_run_at": rule.last_run_at,
                "last_run_ok": rule.last_run_ok,
                "last_run_error": rule.last_run_error,
            }
        )


class NotificationViewSet(OrgScopedViewSet):
    queryset = (
        Notification.objects.select_related("organization", "user", "rule", "content_type")
        .all()
        .order_by("-created_at")
    )
    serializer_class = NotificationSerializer
    http_method_names = ["get", "post", "head", "options"]

    def get_queryset(self):
        # Always require org context; notifications are always viewed through an org.
        org_id = self._resolve_org_id(required=True)
        qs = super().get_queryset().filter(organization_id=int(org_id))

        user = self.request.user
        if not user or not user.is_authenticated:
            return qs.none()
        return qs.filter(user=user)

    def create(self, request, *args, **kwargs):
        raise PermissionDenied("Notifications cannot be created via the API.")

    @action(detail=True, methods=["post"])
    def mark_read(self, request, pk=None, org_id=None, **kwargs):
        n = self.get_object()
        if n.read_at is None:
            n.read_at = timezone.now()
            n.save(update_fields=["read_at"])
        return Response({"ok": True, "read_at": n.read_at})


class WebhookEndpointViewSet(OrgScopedViewSet):
    queryset = WebhookEndpoint.objects.select_related("organization").all().order_by("-enabled", "name", "id")
    serializer_class = WebhookEndpointSerializer
    search_fields = ["name", "url"]

    def perform_create(self, serializer):
        org_id = self._require_org_admin()
        serializer.save(organization_id=org_id)

    def perform_update(self, serializer):
        self._require_org_admin()
        serializer.save()

    def perform_destroy(self, instance):
        self._require_org_admin()
        instance.delete()


class SearchViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    Basic multi-model search endpoint (personal use).
    GET /api/search/?q=foo

    Org selection uses the same rules as other endpoints:
    `?org=<id>`, `X-HomeGlue-Org`, default org, or single membership.
    """

    queryset = Organization.objects.none()
    serializer_class = SearchResponseSerializer

    @extend_schema(
        parameters=[OpenApiParameter(name="q", type=OpenApiTypes.STR, required=True, description="Search query string")],
        responses=SearchResponseSerializer,
    )
    def list(self, request, *args, **kwargs):
        q = (request.query_params.get("q") or "").strip()
        if not q:
            return Response({"results": []})

        org_id = resolve_org_id(request, kwargs=getattr(self, "kwargs", None), required=True)

        results = []
        for model, label, fields in [
            (Contact, "contact", [Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q)]),
            (Asset, "asset", [Q(name__icontains=q) | Q(serial_number__icontains=q)]),
            (ConfigurationItem, "config", [Q(name__icontains=q) | Q(hostname__icontains=q) | Q(primary_ip__icontains=q)]),
            (Document, "document", [Q(title__icontains=q) | Q(body__icontains=q)]),
            (PasswordEntry, "password", [Q(name__icontains=q) | Q(username__icontains=q) | Q(url__icontains=q)]),
            (Domain, "domain", [Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q)]),
            (SSLCertificate, "sslcert", [Q(common_name__icontains=q) | Q(subject_alt_names__icontains=q) | Q(issuer__icontains=q)]),
        ]:
            qs = model.objects.filter(organization_id=org_id).filter(fields[0]).order_by("id")[:10]
            for obj in qs:
                results.append({"type": label, "id": obj.id, "label": str(obj)})

        return Response({"results": results})


class MeViewSet(viewsets.ViewSet):
    """
    Current-user helper endpoints.
    """

    serializer_class = MeSerializer

    @extend_schema(responses=MeSerializer)
    def list(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            raise PermissionDenied("Not authenticated.")

        org_ids = list(OrganizationMembership.objects.filter(user=user).values_list("organization_id", flat=True))
        default_org_id = None
        try:
            default_org_id = user.profile.default_organization_id
        except UserProfile.DoesNotExist:
            default_org_id = None

        return Response(
            {
                "id": user.id,
                "username": user.get_username(),
                "is_superuser": bool(getattr(user, "is_superuser", False)),
                "member_org_ids": org_ids,
                "default_org_id": default_org_id,
            }
        )

    @action(detail=False, methods=["post"], url_path="default-org")
    @extend_schema(request=DefaultOrgRequestSerializer, responses=MeSerializer)
    def set_default_org(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            raise PermissionDenied("Not authenticated.")

        org_id = request.data.get("organization") or request.data.get("org") or request.query_params.get("org")
        org_id = int(org_id) if org_id else None
        if not org_id:
            raise ValidationError({"organization": "Missing organization id."})

        if not (user and user.is_superuser):
            allowed = OrganizationMembership.objects.filter(user=user, organization_id=org_id).exists()
            if not allowed:
                raise PermissionDenied("You do not have access to this organization.")

        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.default_organization_id = org_id
        profile.save(update_fields=["default_organization", "updated_at"])
        return self.list(request)

    @action(detail=False, methods=["get", "post"], url_path="api-token")
    @extend_schema(
        responses={200: ApiTokenStatusSerializer, 201: ApiTokenRotateSerializer},
    )
    def api_token(self, request):
        """
        Personal access token (DRF authtoken).

        GET: returns whether a token exists.
        POST: rotates token and returns the new token value.
        """

        user = request.user
        if not user or not user.is_authenticated:
            raise PermissionDenied("Not authenticated.")

        if request.method.lower() == "get":
            tok = Token.objects.filter(user=user).first()
            return Response({"has_token": bool(tok)})

        Token.objects.filter(user=user).delete()
        tok = Token.objects.create(user=user)
        return Response({"token": tok.key}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="reauth")
    @extend_schema(request=ReauthRequestSerializer, responses=ReauthResponseSerializer)
    def reauth(self, request):
        """
        Obtain a short-lived re-auth token for sensitive operations (password reveal, OTP codes).
        """

        user = request.user
        if not user or not user.is_authenticated:
            raise PermissionDenied("Not authenticated.")
        if not getattr(user, "has_usable_password", lambda: True)():
            raise ValidationError({"password": "This account does not have a local password (SSO-only). Re-auth is not supported yet."})

        pw = (request.data.get("password") or "").strip()
        if not pw or not user.check_password(pw):
            raise ValidationError({"password": "Incorrect password."})

        ttl = _reauth_ttl_seconds()
        tok = sign_reauth_token(user_id=int(user.id))
        return Response({"token": tok, "expires_in": int(ttl)}, status=status.HTTP_200_OK)
