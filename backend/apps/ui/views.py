from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.contrib.auth import update_session_auth_hash
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, IntegrityError
from django.db.models import Q, Count
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST
from django.http import FileResponse
from urllib.parse import urlencode
import csv
import hashlib
import io
import json
from datetime import date, timedelta, datetime
from pathlib import Path
import re
import html
import mimetypes
import zipfile
import difflib

from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import (
    Attachment,
    AttachmentShareLink,
    AttachmentVersion,
    FileFolder,
    CustomField,
    CustomFieldValue,
    Location,
    Note,
    Organization,
    OrganizationMembership,
    Relationship,
    RelationshipType,
    SavedView,
    Tag,
    UserProfile,
)
from apps.docsapp.models import Document, DocumentComment, DocumentFolder, DocumentTemplate, DocumentTemplateComment
from apps.netapp.models import Domain, SSLCertificate
from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem, ChecklistSchedule
from apps.netapp.public_info import (
    apply_domain_public_info,
    apply_ssl_public_info,
    dns_names_for_cert,
    lookup_domain_rdap,
    lookup_tls_certificate,
)
from apps.people.models import Contact
from apps.secretsapp.models import PasswordEntry, PasswordFolder, PasswordShareLink
from apps.secretsapp.totp import TotpError, build_otpauth_url, generate_base32_secret
from apps.audit.models import AuditEvent, AuditPolicy
from rest_framework.authtoken.models import Token
from apps.core.reauth import is_session_reauthed, mark_session_reauthed
from apps.core.system_settings import get_base_url

from apps.integrations.models import ProxmoxConnection, ProxmoxGuest, ProxmoxNetwork, ProxmoxNode
from apps.integrations.proxmox import sync_proxmox_connection

from apps.flexassets.models import FlexibleAsset, FlexibleAssetType
from apps.versionsapp.models import ObjectVersion
from apps.versionsapp.utils import restore_instance_from_snapshot
from apps.workflows.models import Notification, WorkflowRule, WorkflowRuleRun, NotificationDeliveryAttempt, WebhookEndpoint
from apps.workflows.engine import run_rule

from apps.ui.markdown import render_markdown
from apps.backups.models import BackupPolicy, BackupRestoreBundle, BackupSnapshot

from .forms import (
    AssetForm,
    ConfigurationItemForm,
    ContactForm,
    CustomFieldForm,
    FlexibleAssetForm,
    FlexibleAssetTypeForm,
    DocumentForm,
    DocumentCommentForm,
    DocumentTemplateForm,
    DocumentTemplateCommentForm,
    DocumentFolderForm,
    DomainForm,
    FileFolderForm,
    ChecklistForm,
    ChecklistRunForm,
    ChecklistScheduleForm,
    PasswordEntryForm,
    PasswordFolderForm,
    ProxmoxConnectionForm,
    ReauthForm,
    RelationshipForm,
    RelationshipTypeForm,
    SavedViewForm,
    SSLCertificateForm,
    TagForm,
    WorkflowRuleForm,
    WebhookEndpointForm,
)
from .org import clear_current_org, get_allowed_org_qs, get_current_org_context, require_current_org, set_current_org_id


def _reauth_ttl_seconds() -> int:
    try:
        return int(getattr(settings, "HOMEGLUE_REAUTH_TTL_SECONDS", 900) or 900)
    except Exception:
        return 900


def _is_reauthed(request: HttpRequest) -> bool:
    return is_session_reauthed(session=request.session, ttl_seconds=_reauth_ttl_seconds())


@login_required
def reauth_view(request: HttpRequest) -> HttpResponse:
    next_url = (request.GET.get("next") or "").strip() or reverse("ui:dashboard")
    error = None
    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None
    if request.method == "POST":
        form = ReauthForm(request.POST, user=request.user)
        if form.is_valid():
            mark_session_reauthed(session=request.session)
            _audit_event(
                request=request,
                org=org,
                action=AuditEvent.ACTION_UPDATE,
                model="security.ReauthSession",
                object_pk=str(getattr(request.user, "id", "")),
                summary="Session re-authentication succeeded.",
            )
            return redirect(next_url)
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_UPDATE,
            model="security.ReauthSession",
            object_pk=str(getattr(request.user, "id", "")),
            summary="Session re-authentication failed.",
        )
        error = "Please enter your current password."
    else:
        form = ReauthForm(user=request.user)

    return render(request, "ui/reauth.html", {"org": org, "form": form, "next_url": next_url, "error": error})


def _is_org_admin(user, org) -> bool:
    if user and getattr(user, "is_superuser", False):
        return True
    if not user or not user.is_authenticated:
        return False
    m = OrganizationMembership.objects.filter(user=user, organization=org).first()
    return bool(m and m.role in {OrganizationMembership.ROLE_OWNER, OrganizationMembership.ROLE_ADMIN})


def _require_org_admin(user, org) -> None:
    if not _is_org_admin(user, org):
        raise PermissionDenied("Org admin role required.")


def _audit_event(*, request: HttpRequest | None, org, action: str, model: str, object_pk: str, summary: str) -> None:
    """
    Best-effort explicit audit event helper for security/operational events.
    """

    try:
        user = None
        if request is not None and getattr(request, "user", None) and request.user.is_authenticated:
            user = request.user
        ip = None
        if request is not None:
            ip = (request.META.get("REMOTE_ADDR") or "")[:64] or None
        AuditEvent.objects.create(
            organization=org,
            user=user,
            ip=ip,
            action=action,
            model=model,
            object_pk=str(object_pk),
            summary=(summary or "")[:500],
        )
    except Exception:
        pass


def _can_view_document(*, user, org, doc: Document) -> bool:
    if user and getattr(user, "is_superuser", False):
        return True
    if _is_org_admin(user, org):
        return True
    if doc.visibility == Document.VIS_ORG:
        return True
    if doc.visibility == Document.VIS_ADMINS:
        return bool(doc.created_by_id and user and user.is_authenticated and int(doc.created_by_id) == int(user.id))
    if doc.visibility == Document.VIS_PRIVATE:
        return bool(doc.created_by_id and user and user.is_authenticated and int(doc.created_by_id) == int(user.id))
    if doc.visibility == Document.VIS_SHARED:
        if doc.created_by_id and user and user.is_authenticated and int(doc.created_by_id) == int(user.id):
            return True
        if not user or not user.is_authenticated:
            return False
        return doc.allowed_users.filter(id=int(user.id)).exists()
    return False


def _can_view_password(*, user, org, entry: PasswordEntry) -> bool:
    if user and getattr(user, "is_superuser", False):
        return True
    if _is_org_admin(user, org):
        return True
    if entry.visibility == PasswordEntry.VIS_ORG:
        return True
    if entry.visibility == PasswordEntry.VIS_ADMINS:
        return bool(entry.created_by_id and user and user.is_authenticated and int(entry.created_by_id) == int(user.id))
    if entry.visibility == PasswordEntry.VIS_PRIVATE:
        return bool(entry.created_by_id and user and user.is_authenticated and int(entry.created_by_id) == int(user.id))
    if entry.visibility == PasswordEntry.VIS_SHARED:
        if entry.created_by_id and user and user.is_authenticated and int(entry.created_by_id) == int(user.id):
            return True
        if not user or not user.is_authenticated:
            return False
        return entry.allowed_users.filter(id=int(user.id)).exists()
    return False


def _visible_docs_q(user, org) -> Q:
    if user and getattr(user, "is_superuser", False):
        return Q()
    if _is_org_admin(user, org):
        return Q()
    if not user or not user.is_authenticated:
        return Q(pk__in=[])
    return (
        Q(visibility=Document.VIS_ORG)
        | (Q(visibility=Document.VIS_ADMINS) & Q(created_by=user))
        | (Q(visibility=Document.VIS_PRIVATE) & Q(created_by=user))
        | (Q(visibility=Document.VIS_SHARED) & (Q(created_by=user) | Q(allowed_users=user)))
    )


def _doc_review_label(state: str) -> str:
    return {
        Document.REVIEW_DRAFT: "Draft",
        Document.REVIEW_IN_REVIEW: "In review",
        Document.REVIEW_APPROVED: "Approved",
    }.get((state or "").strip(), "Draft")


def _doc_comments_for_document(*, org, doc: Document, limit: int = 200) -> list[DocumentComment]:
    return list(
        DocumentComment.objects.filter(organization=org, document=doc)
        .select_related("created_by")
        .order_by("created_at")[:limit]
    )


def _template_review_label(state: str) -> str:
    return {
        DocumentTemplate.REVIEW_DRAFT: "Draft",
        DocumentTemplate.REVIEW_IN_REVIEW: "In review",
        DocumentTemplate.REVIEW_APPROVED: "Approved",
    }.get((state or "").strip(), "Draft")


def _comments_for_template(*, org, tmpl: DocumentTemplate, limit: int = 200) -> list[DocumentTemplateComment]:
    return list(
        DocumentTemplateComment.objects.filter(organization=org, template=tmpl)
        .select_related("created_by")
        .order_by("created_at")[:limit]
    )


def _create_doc_mention_notifications(*, org, doc: Document, comment: DocumentComment, actor) -> int:
    body = (comment.body or "").strip()
    if not body:
        return 0
    usernames = {m.lower() for m in re.findall(r"(?<!\w)@([A-Za-z0-9_.-]{3,150})", body)}
    if not usernames:
        return 0

    memberships = (
        OrganizationMembership.objects.filter(organization=org)
        .select_related("user")
        .order_by("user_id")
    )
    users_by_name = {}
    for m in memberships:
        u = getattr(m, "user", None)
        uname = (getattr(u, "username", "") or "").strip().lower()
        if not u or not uname:
            continue
        users_by_name[uname] = u

    ct = ContentType.objects.get_for_model(Document)
    actor_name = getattr(actor, "username", "Someone")
    created = 0
    for uname in sorted(usernames):
        user = users_by_name.get(uname)
        if not user:
            continue
        if actor and getattr(actor, "id", None) and int(user.id) == int(actor.id):
            continue
        if not _can_view_document(user=user, org=org, doc=doc):
            continue
        dedupe_key = f"doc_comment_mention:{comment.id}:{int(user.id)}"
        obj, was_created = Notification.objects.get_or_create(
            organization=org,
            user=user,
            dedupe_key=dedupe_key,
            defaults={
                "level": Notification.LEVEL_INFO,
                "title": f"Mention in document: {doc.title}",
                "body": f"{actor_name} mentioned you in a document comment.",
                "content_type": ct,
                "object_id": str(doc.id),
            },
        )
        if was_created and obj:
            created += 1
    return created


def _create_template_mention_notifications(*, org, tmpl: DocumentTemplate, comment: DocumentTemplateComment, actor) -> int:
    body = (comment.body or "").strip()
    if not body:
        return 0
    usernames = {m.lower() for m in re.findall(r"(?<!\w)@([A-Za-z0-9_.-]{3,150})", body)}
    if not usernames:
        return 0

    memberships = (
        OrganizationMembership.objects.filter(organization=org)
        .select_related("user")
        .order_by("user_id")
    )
    users_by_name = {}
    for m in memberships:
        u = getattr(m, "user", None)
        uname = (getattr(u, "username", "") or "").strip().lower()
        if not u or not uname:
            continue
        users_by_name[uname] = u

    ct = ContentType.objects.get_for_model(DocumentTemplate)
    actor_name = getattr(actor, "username", "Someone")
    created = 0
    for uname in sorted(usernames):
        user = users_by_name.get(uname)
        if not user:
            continue
        if actor and getattr(actor, "id", None) and int(user.id) == int(actor.id):
            continue
        dedupe_key = f"template_comment_mention:{comment.id}:{int(user.id)}"
        obj, was_created = Notification.objects.get_or_create(
            organization=org,
            user=user,
            dedupe_key=dedupe_key,
            defaults={
                "level": Notification.LEVEL_INFO,
                "title": f"Mention in template: {tmpl.name}",
                "body": f"{actor_name} mentioned you in a template comment.",
                "content_type": ct,
                "object_id": str(tmpl.id),
            },
        )
        if was_created and obj:
            created += 1
    return created


def _visible_passwords_q(user, org) -> Q:
    if user and getattr(user, "is_superuser", False):
        return Q()
    if _is_org_admin(user, org):
        return Q()
    if not user or not user.is_authenticated:
        return Q(pk__in=[])
    return (
        Q(visibility=PasswordEntry.VIS_ORG)
        | (Q(visibility=PasswordEntry.VIS_ADMINS) & Q(created_by=user))
        | (Q(visibility=PasswordEntry.VIS_PRIVATE) & Q(created_by=user))
        | (Q(visibility=PasswordEntry.VIS_SHARED) & (Q(created_by=user) | Q(allowed_users=user)))
    )


def _crumbs(*items):
    """
    Build breadcrumb list for templates.
    Each item: (label, url_or_None)
    """

    crumbs = [{"label": "Dashboard", "url": reverse("ui:dashboard")}]
    for label, url in items:
        crumbs.append({"label": label, "url": url})
    return crumbs


def _folder_path_map(*, folders) -> dict[int, dict[str, object]]:
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


def _doc_folder_crumb_items(*, folder: DocumentFolder) -> list[tuple[str, str]]:
    """
    Return crumbs (label, url) for folder ancestry, root->folder.
    """

    chain = []
    cur = folder
    seen = set()
    while cur is not None and getattr(cur, "id", None):
        cid = int(cur.id)
        if cid in seen:
            break
        seen.add(cid)
        chain.append(cur)
        cur = getattr(cur, "parent", None)
    chain.reverse()
    return [(f.name, reverse("ui:document_folder_detail", kwargs={"folder_id": f.id})) for f in chain]

def _delete_relationships_for_object(org, model_cls, obj_id: int) -> int:
    """
    Relationships use generic refs; deleting a referenced object can leave orphans.
    We proactively delete in-org relationships that point at the object.
    """

    ct = ContentType.objects.get_for_model(model_cls)
    oid = str(int(obj_id))
    qs = Relationship.objects.filter(organization=org).filter(
        (Q(source_content_type=ct) & Q(source_object_id=oid))
        | (Q(target_content_type=ct) & Q(target_object_id=oid))
    )
    n = qs.count()
    qs.delete()
    return n


def _delete_generic_refs_for_object(org, model_cls, obj_id: int) -> dict[str, int]:
    """
    Best-effort cleanup for generic "attached" records (relationships, attachments, notes, custom field values)
    that won't cascade automatically when the referenced object is deleted.
    """

    ct = ContentType.objects.get_for_model(model_cls)
    oid = str(int(obj_id))

    n_rel = _delete_relationships_for_object(org, model_cls, obj_id)

    atts = list(Attachment.objects.filter(organization=org, content_type=ct, object_id=oid))
    n_att = len(atts)
    for a in atts:
        a.delete()  # also removes underlying media file

    n_cf = CustomFieldValue.objects.filter(organization=org, content_type=ct, object_id=oid).count()
    CustomFieldValue.objects.filter(organization=org, content_type=ct, object_id=oid).delete()

    n_notes = Note.objects.filter(organization=org, content_type=ct, object_id=oid).count()
    Note.objects.filter(organization=org, content_type=ct, object_id=oid).delete()

    return {"relationships": n_rel, "attachments": n_att, "notes": n_notes, "custom_field_values": n_cf}


def _tags_available_for_org(org):
    return Tag.objects.select_related("organization").filter(Q(organization__isnull=True) | Q(organization=org)).order_by("name")


def _is_edit_mode(request: HttpRequest) -> bool:
    v = (request.GET.get("edit") or "").strip().lower()
    return v in {"1", "true", "yes", "on"}


def _can_view_attachment(*, request: HttpRequest, org, a: Attachment) -> bool:
    """
    Attachments inherit org scoping. If attached to restricted Docs/Passwords, enforce ACLs.
    """

    if a.organization_id != org.id:
        return False
    ct = getattr(a, "content_type", None)
    oid = getattr(a, "object_id", None)
    if not (ct and oid):
        return True
    try:
        model_cls = ct.model_class()
    except Exception:
        model_cls = None
    if model_cls is None:
        return True
    try:
        if model_cls is Document:
            doc = Document.objects.filter(organization=org, id=int(oid)).first()
            return bool(doc and _can_view_document(user=request.user, org=org, doc=doc))
        if model_cls is PasswordEntry:
            entry = PasswordEntry.objects.filter(organization=org, id=int(oid)).first()
            return bool(entry and _can_view_password(user=request.user, org=org, entry=entry))
    except Exception:
        return False
    return True


def _attachments_queryset_visible_to_user(*, request: HttpRequest, org):
    qs = Attachment.objects.filter(organization=org).select_related("uploaded_by", "content_type").order_by("-created_at")
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)
    if can_admin:
        return qs

    # Hide attachments attached to restricted docs/passwords.
    doc_ct = ContentType.objects.get_for_model(Document)
    pw_ct = ContentType.objects.get_for_model(PasswordEntry)
    doc_ids = list(Document.objects.filter(organization=org).filter(_visible_docs_q(request.user, org)).values_list("id", flat=True)[:5000])
    pw_ids = list(PasswordEntry.objects.filter(organization=org).filter(_visible_passwords_q(request.user, org)).values_list("id", flat=True)[:5000])
    qs = qs.exclude(Q(content_type=doc_ct) & ~Q(object_id__in=[str(i) for i in doc_ids]))
    qs = qs.exclude(Q(content_type=pw_ct) & ~Q(object_id__in=[str(i) for i in pw_ids]))
    return qs

_MODEL_KEY_TO_LIST_URL = {
    SavedView.KEY_ASSET: "ui:assets_list",
    SavedView.KEY_CONFIG_ITEM: "ui:config_items_list",
    SavedView.KEY_CONTACT: "ui:contacts_list",
    SavedView.KEY_LOCATION: "ui:locations_list",
    SavedView.KEY_DOCUMENT: "ui:documents_list",
    SavedView.KEY_TEMPLATE: "ui:templates_list",
    SavedView.KEY_PASSWORD: "ui:passwords_list",
    SavedView.KEY_DOMAIN: "ui:domains_list",
    SavedView.KEY_SSL_CERT: "ui:sslcerts_list",
    SavedView.KEY_FILE: "ui:files_list",
}


def _wiki_root() -> Path:
    """
    Wiki markdown lives in backend/wiki so it is shipped with the Docker image (compose build context is ./backend).
    """

    # views.py: /app/apps/ui/views.py -> parents[2] == /app
    return Path(__file__).resolve().parents[2] / "wiki"


_WIKI_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\\-]*$", re.IGNORECASE)


_WIKI_A_HREF_RE = re.compile(r'(<a\\b[^>]*\\bhref=")([^"]+)(")', re.IGNORECASE)


def _rewrite_wiki_internal_links(html: str, *, page_view_name: str) -> str:
    """
    Rewrite relative markdown links like `assets.md` to the in-app wiki routes.
    This keeps shipped wiki pages navigable without requiring absolute URLs.
    """

    def _repl(m: re.Match) -> str:
        prefix, href, suffix = m.group(1), m.group(2), m.group(3)

        # Leave absolute/explicit links alone.
        if href.startswith(("http://", "https://", "mailto:", "/", "#")):
            return m.group(0)
        if href.lower().startswith("javascript:"):
            return m.group(0)

        if "#" in href:
            base, frag = href.split("#", 1)
        else:
            base, frag = href, ""

        if not base.lower().endswith(".md"):
            return m.group(0)

        slug = Path(base).name[:-3]  # strip ".md"
        if not _WIKI_SLUG_RE.fullmatch(slug):
            return m.group(0)

        new_href = reverse(page_view_name, kwargs={"slug": slug})
        if frag:
            new_href += f"#{frag}"
        return f'{prefix}{new_href}{suffix}'

    return _WIKI_A_HREF_RE.sub(_repl, html or "")


def _render_markdown_simple(md: str, *, page_view_name: str) -> str:
    """
    Markdown-to-HTML renderer for the in-app wiki.
    Prefers Python-Markdown + bleach sanitization; falls back to a minimal safe renderer.
    """

    # Use the same safe renderer as user-entered markdown (Docs/Notes/etc),
    # then rewrite relative wiki links to in-app routes.
    cleaned = render_markdown(md or "")
    return _rewrite_wiki_internal_links(cleaned, page_view_name=page_view_name)


def _wiki_pages_index(*, page_view_name: str) -> list[dict]:
    """
    Build an index of shipped wiki markdown pages.
    """

    root = _wiki_root()
    pages: list[dict] = []
    for p in sorted(root.glob("*.md")):
        slug = p.stem
        title = slug
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.startswith("# "):
                    title = line[2:].strip() or slug
                    break
        except Exception:
            title = slug
        pages.append(
            {
                "slug": slug,
                "title": title,
                "path": p,
                "url": reverse(page_view_name, kwargs={"slug": slug}),
            }
        )
    return pages


def _wiki_load_nav(pages_by_slug: dict[str, dict]) -> dict:
    """
    Load wiki navigation from backend/wiki/_nav.json (shipped with the image).
    """

    import json

    nav_path = _wiki_root() / "_nav.json"
    if not nav_path.exists():
        return {"home": None, "sections": []}
    try:
        raw = json.loads(nav_path.read_text(encoding="utf-8"))
    except Exception:
        return {"home": None, "sections": []}

    home = (raw or {}).get("home") or None
    if home and home not in pages_by_slug:
        home = None

    out_sections = []
    for sec in (raw or {}).get("sections") or []:
        sec_title = (sec or {}).get("title") or "Section"
        items_out = []
        for it in (sec or {}).get("items") or []:
            slug = (it or {}).get("slug") or ""
            if slug not in pages_by_slug:
                continue
            item_title = (it or {}).get("title") or pages_by_slug[slug]["title"]
            items_out.append({"slug": slug, "title": item_title})
        if items_out:
            out_sections.append({"title": sec_title, "items": items_out})

    return {"home": home, "sections": out_sections}


def _wiki_nav_context(*, active_slug: str | None, q: str, page_view_name: str) -> dict:
    pages = _wiki_pages_index(page_view_name=page_view_name)
    pages_by_slug = {p["slug"]: p for p in pages}
    nav = _wiki_load_nav(pages_by_slug=pages_by_slug)

    home_slug = nav.get("home") or ("documentation" if "documentation" in pages_by_slug else (pages[0]["slug"] if pages else None))
    home_title = pages_by_slug.get(home_slug, {}).get("title") if home_slug else "Wiki"

    nav_sections = []
    seen = set()
    for sec in nav.get("sections") or []:
        items = []
        for it in sec.get("items") or []:
            slug = it["slug"]
            seen.add(slug)
            items.append(
                {
                    "slug": slug,
                    "title": it["title"],
                    "url": pages_by_slug[slug]["url"],
                    "active": bool(active_slug and slug == active_slug),
                }
            )
        if items:
            nav_sections.append({"title": sec.get("title") or "Section", "items": items})

    other = []
    for p in pages:
        if p["slug"] in seen:
            continue
        if p["slug"].lower() == "readme":
            continue
        other.append(
            {
                "slug": p["slug"],
                "title": p["title"],
                "url": p["url"],
                "active": bool(active_slug and p["slug"] == active_slug),
            }
        )
    if other:
        nav_sections.append({"title": "Other", "items": other})

    return {
        "wiki_q": q,
        "wiki_nav": nav_sections,
        "wiki_home_slug": home_slug,
        "wiki_home_title": home_title,
        "wiki_pages": pages,
        "wiki_pages_by_slug": pages_by_slug,
    }


def _saved_views_for(*, org, model_key: str):
    qs = SavedView.objects.filter(organization=org, model_key=model_key).order_by("name")
    return list(qs)


def _apply_saved_view_q(*, request: HttpRequest, org, model_key: str, q: str) -> tuple[str, SavedView | None]:
    """
    If `view=<id>` is present and no explicit `q` is provided, load q from the SavedView.
    """

    view_id = request.GET.get("view")
    if not view_id or q:
        return q, None
    if not str(view_id).isdigit():
        return q, None
    sv = SavedView.objects.filter(organization=org, model_key=model_key, id=int(view_id)).first()
    if not sv:
        return q, None
    try:
        q2 = (sv.params or {}).get("q") or ""
    except Exception:
        q2 = ""
    return (q2 or "").strip(), sv


def _apply_saved_view_params(*, request: HttpRequest, org, model_key: str, params: dict[str, str]) -> tuple[dict[str, str], SavedView | None]:
    """
    Apply saved-view params when `view=<id>` is selected.
    Explicit query params in the current request always win.
    """

    view_id = request.GET.get("view")
    if not view_id or not str(view_id).isdigit():
        return params, None
    sv = SavedView.objects.filter(organization=org, model_key=model_key, id=int(view_id)).first()
    if not sv:
        return params, None

    out = dict(params or {})
    explicit = set(request.GET.keys())
    try:
        saved = dict(sv.params or {})
    except Exception:
        saved = {}

    for k, v in saved.items():
        if k in explicit:
            continue
        out[k] = str(v or "").strip()
    return out, sv


def _save_view_new_url(*, request: HttpRequest, model_key: str, q: str, params: dict | None = None) -> str:
    qs_data = {"model_key": model_key, "next": request.get_full_path(), "q": q or ""}
    if params:
        try:
            qs_data["params_json"] = json.dumps(params, sort_keys=True)
        except Exception:
            pass
    qs = urlencode(qs_data)
    return reverse("ui:saved_view_new") + "?" + qs


def _url_for_object_detail(obj) -> str:
    """
    Best-effort object -> UI detail URL mapping, used by generic actions (e.g. restore).
    """

    if isinstance(obj, Asset):
        return reverse("ui:asset_detail", kwargs={"asset_id": obj.id})
    if isinstance(obj, ConfigurationItem):
        return reverse("ui:config_item_detail", kwargs={"item_id": obj.id})
    if isinstance(obj, Document):
        return reverse("ui:document_detail", kwargs={"document_id": obj.id})
    if isinstance(obj, DocumentTemplate):
        return reverse("ui:template_detail", kwargs={"template_id": obj.id})
    if isinstance(obj, PasswordEntry):
        return reverse("ui:password_detail", kwargs={"password_id": obj.id})
    if isinstance(obj, PasswordFolder):
        return reverse("ui:password_folder_detail", kwargs={"folder_id": obj.id})
    if isinstance(obj, Domain):
        return reverse("ui:domain_detail", kwargs={"domain_id": obj.id})
    if isinstance(obj, SSLCertificate):
        return reverse("ui:sslcert_detail", kwargs={"sslcert_id": obj.id})
    if isinstance(obj, Checklist):
        return reverse("ui:checklist_detail", kwargs={"checklist_id": obj.id})
    if isinstance(obj, ChecklistRun):
        return reverse("ui:checklist_run_detail", kwargs={"run_id": obj.id})
    if isinstance(obj, FlexibleAsset):
        return reverse("ui:flex_asset_detail", kwargs={"type_id": obj.asset_type_id, "asset_id": obj.id})
    if isinstance(obj, FlexibleAssetType):
        return reverse("ui:flex_type_detail", kwargs={"type_id": obj.id})
    if isinstance(obj, Location):
        return reverse("ui:location_detail", kwargs={"location_id": obj.id})
    if isinstance(obj, Contact):
        return reverse("ui:contact_detail", kwargs={"contact_id": obj.id})
    return reverse("ui:dashboard")


def _is_postgres() -> bool:
    try:
        return connection.vendor == "postgresql"
    except Exception:
        return False


def _notes_qs_for_user(*, user, org):
    """
    Notes can be attached to restricted objects (Docs/Passwords); non-admins must not see those.
    Keep this logic centralized so search + views stay consistent with Notes list.
    """

    qs = Note.objects.filter(organization=org).select_related("created_by", "content_type").order_by("-created_at")
    can_admin = _is_org_admin(user, org) or getattr(user, "is_superuser", False)
    if can_admin:
        return qs

    doc_ct = ContentType.objects.get_for_model(Document)
    pw_ct = ContentType.objects.get_for_model(PasswordEntry)
    doc_ids = list(Document.objects.filter(organization=org).filter(_visible_docs_q(user, org)).values_list("id", flat=True)[:5000])
    pw_ids = list(PasswordEntry.objects.filter(organization=org).filter(_visible_passwords_q(user, org)).values_list("id", flat=True)[:5000])
    qs = qs.exclude(Q(content_type=doc_ct) & ~Q(object_id__in=[str(i) for i in doc_ids]))
    qs = qs.exclude(Q(content_type=pw_ct) & ~Q(object_id__in=[str(i) for i in pw_ids]))
    return qs


def _attachments_qs_for_user(*, user, org):
    """
    Attachments can be linked to restricted objects (Docs/Passwords); non-admins must not see those.
    Keep this logic centralized so search + lists stay consistent.
    """

    qs = Attachment.objects.filter(organization=org).select_related("uploaded_by", "content_type", "folder").order_by("-created_at")
    can_admin = _is_org_admin(user, org) or getattr(user, "is_superuser", False)
    if can_admin:
        return qs

    doc_ct = ContentType.objects.get_for_model(Document)
    pw_ct = ContentType.objects.get_for_model(PasswordEntry)
    doc_ids = list(Document.objects.filter(organization=org).filter(_visible_docs_q(user, org)).values_list("id", flat=True)[:5000])
    pw_ids = list(PasswordEntry.objects.filter(organization=org).filter(_visible_passwords_q(user, org)).values_list("id", flat=True)[:5000])
    qs = qs.exclude(Q(content_type=doc_ct) & ~Q(object_id__in=[str(i) for i in doc_ids]))
    qs = qs.exclude(Q(content_type=pw_ct) & ~Q(object_id__in=[str(i) for i in pw_ids]))
    return qs


def _fts_ranked(qs, *, q: str, vector, rank_field: str = "_fts_rank"):
    """
    Apply Postgres full-text search ranking. Caller must pass a SearchVector-like expression.
    Falls back to returning the input queryset on error.
    """

    try:
        from django.contrib.postgres.search import SearchQuery, SearchRank

        query = SearchQuery(q, search_type="websearch")
        qs = qs.annotate(**{rank_field: SearchRank(vector, query)}).filter(**{f"{rank_field}__gt": 0.0}).order_by(f"-{rank_field}")
        return qs
    except Exception:
        return qs


def _snippet_html_from_headline(raw: str) -> str:
    """
    Convert a Postgres SearchHeadline() string to safe HTML.

    We avoid trusting DB-returned headline HTML by using marker tokens
    in the DB expression and converting them to <mark> after escaping.
    """

    s = str(raw or "")
    if not s.strip():
        return ""
    # Escape any user content, then translate our highlight markers.
    s = html.escape(s)
    s = s.replace("[[[", "<mark>").replace("]]]", "</mark>")
    return s


def _snippet_html_from_text(text: str, q: str, *, max_len: int = 180) -> str:
    """
    Fallback snippet builder for non-Postgres DBs.
    Escapes everything and highlights the first match (case-insensitive).
    """

    t = str(text or "").strip()
    needle = (q or "").strip()
    if not t or not needle:
        return ""
    lt = t.lower()
    ln = needle.lower()
    i = lt.find(ln)
    if i < 0:
        # No match; return a small escaped prefix.
        return html.escape(t[:max_len]) + ("..." if len(t) > max_len else "")
    start = max(i - (max_len // 3), 0)
    end = min(start + max_len, len(t))
    frag = t[start:end]
    # Highlight first occurrence within frag.
    lfrag = frag.lower()
    j = lfrag.find(ln)
    if j < 0:
        return html.escape(frag) + ("..." if end < len(t) else "")
    before = html.escape(frag[:j])
    hit = html.escape(frag[j : j + len(needle)])
    after = html.escape(frag[j + len(needle) :])
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(t) else ""
    return f"{prefix}{before}<mark>{hit}</mark>{after}{suffix}"


def _qs_suffix(request: HttpRequest) -> str:
    s = (request.META.get("QUERY_STRING") or "").strip()
    return ("?" + s) if s else ""


def _csv_http_response(*, filename: str, header: list[str], rows: list[list[str]]) -> HttpResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    resp = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


def _redirect_back(request: HttpRequest, *, fallback_url: str) -> HttpResponse:
    nxt = (request.POST.get("next") or request.GET.get("next") or "").strip()
    if nxt.startswith("/"):
        return redirect(nxt)
    return redirect(fallback_url)


def _archived_mode(request: HttpRequest) -> str:
    """
    Interpret `?archived=` for list filtering.

    - (missing) => "active" (default)
    - "1"/true/on/only => "only" (archived only)
    - "all"/include => "include" (active + archived)
    """

    raw = (request.GET.get("archived") or "").strip().lower()
    if raw in {"1", "true", "yes", "on", "only"}:
        return "only"
    if raw in {"all", "include"}:
        return "include"
    return "active"


def _filter_archived_qs(request: HttpRequest, qs):
    """
    Apply archived filtering to a queryset if the model supports `archived_at`.
    """

    if not hasattr(qs.model, "archived_at"):
        return qs
    mode = _archived_mode(request)
    if mode == "include":
        return qs
    if mode == "only":
        return qs.filter(archived_at__isnull=False)
    return qs.filter(archived_at__isnull=True)


def _archived_toggle_urls(request: HttpRequest) -> tuple[str, str]:
    """
    Return (active_url, archived_url) for the current path, preserving other query params.
    """

    params = request.GET.copy()
    params.pop("archived", None)
    base = request.path
    active_url = base + (("?" + params.urlencode()) if params else "")
    params["archived"] = "1"
    archived_url = base + "?" + params.urlencode()
    return active_url, archived_url


def _bulk_action(
    request: HttpRequest,
    *,
    org,
    model_cls,
    base_qs,
    list_url_name: str,
    supports_tags: bool,
) -> HttpResponse:
    ids = [int(x) for x in request.POST.getlist("ids") if (x or "").isdigit()]
    action = (request.POST.get("action") or "").strip()
    if not ids:
        return _redirect_back(request, fallback_url=reverse(list_url_name))

    qs = base_qs.filter(id__in=ids)

    if action in {"archive", "delete"}:
        # Back-compat: older UI posts "delete". For archivable models this becomes "archive".
        if hasattr(model_cls, "archived_at"):
            _require_org_admin(request.user, org)
            now = timezone.now()
            for obj in list(qs):
                if getattr(obj, "archived_at", None) is None:
                    obj.archived_at = now
                    obj.save(update_fields=["archived_at"])
            return _redirect_back(request, fallback_url=reverse(list_url_name))

        # Non-archivable: keep hard delete behavior.
        _require_org_admin(request.user, org)
        for obj in list(qs):
            _delete_generic_refs_for_object(org, model_cls, int(obj.id))
            obj.delete()
        return _redirect_back(request, fallback_url=reverse(list_url_name))

    if action == "tag_add" and supports_tags:
        tag_id = request.POST.get("tag_id")
        tag_id = int(tag_id) if (tag_id or "").isdigit() else None
        if not tag_id:
            return _redirect_back(request, fallback_url=reverse(list_url_name))
        tag = _tags_available_for_org(org).filter(id=tag_id).first()
        if not tag:
            return _redirect_back(request, fallback_url=reverse(list_url_name))
        for obj in list(qs):
            obj.tags.add(tag)
        return _redirect_back(request, fallback_url=reverse(list_url_name))

    return _redirect_back(request, fallback_url=reverse(list_url_name))


def _ref_for_obj(obj) -> str:
    ct = ContentType.objects.get_for_model(obj.__class__)
    return f"{ct.app_label}.{ct.model}:{obj.pk}"


def _ref_prefix_for_model(model_cls) -> str:
    ct = ContentType.objects.get_for_model(model_cls)
    return f"{ct.app_label}.{ct.model}:"


def _parse_ref(ref: str):
    """
    Parse "app_label.model:pk" into (ContentType, object_id_str) or return None.
    """

    ref = (ref or "").strip()
    if not ref or ":" not in ref or "." not in ref:
        return None
    left, right = ref.split(":", 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        return None
    if not right.isdigit():
        return None
    app_label, model = left.split(".", 1)
    if not app_label or not model:
        return None
    ct = ContentType.objects.filter(app_label=app_label, model=model).first()
    if not ct:
        return None
    return ct, str(int(right))


def _relationships_for_object(*, org, obj, limit: int = 50) -> list[Relationship]:
    """
    Relationships are stored generically; filter by (content_type, object_id) to avoid collisions
    between different models that might share the same numeric PK.
    """

    ct = ContentType.objects.get_for_model(obj.__class__)
    oid = str(obj.pk)
    return list(
        Relationship.objects.filter(organization=org)
        .filter(
            (Q(source_content_type=ct) & Q(source_object_id=oid))
            | (Q(target_content_type=ct) & Q(target_object_id=oid))
        )
        .select_related("relationship_type", "source_content_type", "target_content_type")
        .order_by("-created_at")[:limit]
    )


def _relationships_view(*, request: HttpRequest, org, relationships: list[Relationship]) -> list[dict]:
    """
    Build relationship display rows while avoiding leaking labels for restricted objects (docs/passwords).
    """

    if not relationships:
        return []

    # Bulk resolve docs/passwords with ACL applied.
    doc_ct = ContentType.objects.get_for_model(Document)
    pw_ct = ContentType.objects.get_for_model(PasswordEntry)

    doc_ids: set[int] = set()
    pw_ids: set[int] = set()
    for r in relationships:
        if int(r.source_content_type_id) == int(doc_ct.id):
            doc_ids.add(int(r.source_object_id))
        if int(r.target_content_type_id) == int(doc_ct.id):
            doc_ids.add(int(r.target_object_id))
        if int(r.source_content_type_id) == int(pw_ct.id):
            pw_ids.add(int(r.source_object_id))
        if int(r.target_content_type_id) == int(pw_ct.id):
            pw_ids.add(int(r.target_object_id))

    doc_map: dict[str, dict] = {}
    if doc_ids:
        dqs = Document.objects.filter(organization=org, id__in=list(doc_ids))
        if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
            dqs = dqs.filter(_visible_docs_q(request.user, org)).distinct()
        for d in dqs:
            doc_map[str(d.id)] = {"label": d.title, "url": reverse("ui:document_detail", kwargs={"document_id": d.id})}

    pw_map: dict[str, dict] = {}
    if pw_ids:
        pqs = PasswordEntry.objects.filter(organization=org, id__in=list(pw_ids))
        if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
            pqs = pqs.filter(_visible_passwords_q(request.user, org)).distinct()
        for p in pqs:
            pw_map[str(p.id)] = {"label": p.name, "url": reverse("ui:password_detail", kwargs={"password_id": p.id})}

    rows: list[dict] = []
    for r in relationships:
        src_label = None
        src_url = None
        tgt_label = None
        tgt_url = None

        if int(r.source_content_type_id) == int(doc_ct.id):
            v = doc_map.get(str(r.source_object_id))
            src_label = v["label"] if v else "(restricted)"
            src_url = v["url"] if v else None
        elif int(r.source_content_type_id) == int(pw_ct.id):
            v = pw_map.get(str(r.source_object_id))
            src_label = v["label"] if v else "(restricted)"
            src_url = v["url"] if v else None
        else:
            src_label = r.source_label()
            src_url = _ui_object_url(r.source_content_type.app_label, r.source_content_type.model, r.source_object_id)

        if int(r.target_content_type_id) == int(doc_ct.id):
            v = doc_map.get(str(r.target_object_id))
            tgt_label = v["label"] if v else "(restricted)"
            tgt_url = v["url"] if v else None
        elif int(r.target_content_type_id) == int(pw_ct.id):
            v = pw_map.get(str(r.target_object_id))
            tgt_label = v["label"] if v else "(restricted)"
            tgt_url = v["url"] if v else None
        else:
            tgt_label = r.target_label()
            tgt_url = _ui_object_url(r.target_content_type.app_label, r.target_content_type.model, r.target_object_id)

        rows.append(
            {
                "id": r.id,
                "type_name": r.relationship_type.name,
                "created_at": r.created_at,
                "notes": r.notes,
                "source": {"label": src_label, "url": src_url},
                "target": {"label": tgt_label, "url": tgt_url},
                "label": f"{src_label} -> {tgt_label}",
            }
        )
    return rows


def _relationship_counts_for_model(*, org, model_cls, ids: list[int]) -> dict[int, int]:
    """
    Count relationships per object for a given model within an org.
    Uses (content_type, object_id) matching to avoid collisions across models.
    """

    ids = [int(i) for i in ids if i is not None]
    if not ids:
        return {}
    ct = ContentType.objects.get_for_model(model_cls)
    ids_str = [str(i) for i in ids]
    want = set(ids_str)
    counts: dict[int, int] = {}

    qs = (
        Relationship.objects.filter(organization=org)
        .filter(
            (Q(source_content_type=ct) & Q(source_object_id__in=ids_str))
            | (Q(target_content_type=ct) & Q(target_object_id__in=ids_str))
        )
        .values_list("source_content_type_id", "source_object_id", "target_content_type_id", "target_object_id")
    )

    for sct_id, sid, tct_id, tid in qs:
        if int(sct_id) == int(ct.id) and sid in want:
            counts[int(sid)] = counts.get(int(sid), 0) + 1
        if int(tct_id) == int(ct.id) and tid in want:
            counts[int(tid)] = counts.get(int(tid), 0) + 1

    return counts


def _attachments_for_object(*, org, obj) -> list[Attachment]:
    ct = ContentType.objects.get_for_model(obj.__class__)
    return list(
        Attachment.objects.filter(organization=org, content_type=ct, object_id=str(obj.pk))
        .select_related("uploaded_by")
        .order_by("-created_at")
    )

def _notes_for_object(*, org, obj, limit: int = 50) -> list[Note]:
    ct = ContentType.objects.get_for_model(obj.__class__)
    return list(
        Note.objects.filter(organization=org, content_type=ct, object_id=str(obj.pk))
        .select_related("created_by")
        .order_by("-created_at")[:limit]
    )


def _create_attachment(*, org, obj, uploaded_by, file) -> None:
    if not file:
        return
    ct = ContentType.objects.get_for_model(obj.__class__)
    Attachment.objects.create(
        organization=org,
        uploaded_by=uploaded_by if (uploaded_by and uploaded_by.is_authenticated) else None,
        file=file,
        content_type=ct,
        object_id=str(obj.pk),
    )


def _custom_fields_for_model(*, org, model_cls) -> list[CustomField]:
    ct = ContentType.objects.get_for_model(model_cls)
    return list(CustomField.objects.filter(organization=org, content_type=ct, flexible_asset_type__isnull=True).order_by("sort_order", "name"))


def _custom_fields_for_flex_asset(*, org, asset_type: FlexibleAssetType) -> list[CustomField]:
    ct = ContentType.objects.get_for_model(FlexibleAsset)
    type_fields = list(
        CustomField.objects.filter(organization=org, content_type=ct, flexible_asset_type=asset_type).order_by("sort_order", "name")
    )
    common = list(
        CustomField.objects.filter(organization=org, content_type=ct, flexible_asset_type__isnull=True).order_by("sort_order", "name")
    )
    return type_fields + common


def _custom_field_values_for_object(*, org, obj) -> dict[int, str]:
    ct = ContentType.objects.get_for_model(obj.__class__)
    qs = CustomFieldValue.objects.filter(organization=org, content_type=ct, object_id=str(obj.pk)).select_related("field")
    return {int(v.field_id): (v.value_text or "") for v in qs}


def _save_custom_fields_from_post(*, request: HttpRequest, org, obj) -> None:
    if isinstance(obj, FlexibleAsset):
        defs = _custom_fields_for_flex_asset(org=org, asset_type=obj.asset_type)
    else:
        defs = _custom_fields_for_model(org=org, model_cls=obj.__class__)
    ct = ContentType.objects.get_for_model(obj.__class__)
    for f in defs:
        name = f"cf_{f.id}"
        if f.field_type == CustomField.TYPE_BOOLEAN:
            raw = "1" if request.POST.get(name) else ""
        else:
            raw = (request.POST.get(name) or "").strip()

        existing = CustomFieldValue.objects.filter(
            organization=org, field=f, content_type=ct, object_id=str(obj.pk)
        ).first()

        if not raw:
            if existing:
                existing.delete()
            continue

        if existing:
            if existing.value_text != raw:
                existing.value_text = raw
                existing.save(update_fields=["value_text", "updated_at"])
        else:
            CustomFieldValue.objects.create(
                organization=org, field=f, content_type=ct, object_id=str(obj.pk), value_text=raw
            )


def _human_model_label(model: str) -> str:
    raw = (model or "").strip()
    if "." in raw:
        app, name = raw.split(".", 1)
    else:
        app, name = "system", raw
    app_labels = {
        "core": "Core",
        "assets": "Assets",
        "people": "People",
        "docsapp": "Docs",
        "secretsapp": "Passwords",
        "netapp": "Network",
        "checklists": "Checklists",
        "flexassets": "Flexible Assets",
        "integrations": "Integrations",
        "workflows": "Workflows",
        "backups": "Backups",
        "audit": "Audit",
        "security": "Security",
        "versionsapp": "Versions",
        "system": "System",
    }
    app_label = app_labels.get(app.lower(), app.replace("_", " ").title())
    # Convert CamelCase / snake_case -> title words.
    nice = re.sub(r"(?<!^)([A-Z])", r" \1", name).replace("_", " ").strip().title()
    if not nice:
        nice = name or "Event"
    return f"{app_label} / {nice}"


def _human_action_label(action: str) -> str:
    val = (action or "").strip().lower()
    return {
        AuditEvent.ACTION_CREATE: "Created",
        AuditEvent.ACTION_UPDATE: "Updated",
        AuditEvent.ACTION_DELETE: "Deleted",
    }.get(val, (action or "Event").title())


def _human_ct_label(ct) -> str:
    if not ct:
        return "Item"
    return _human_model_label(f"{ct.app_label}.{ct.model}")


def _human_ref_label(*, ct, oid: str | int | None = None, obj=None, restricted: bool = False) -> str:
    base = _human_ct_label(ct)
    if restricted:
        return f"{base}: Restricted"
    if obj is not None:
        return f"{base}: {obj}"
    if oid is not None and str(oid).strip():
        return f"{base} #{oid}"
    return base


def _audit_event_view_row(e: AuditEvent) -> dict:
    return {
        "ts": e.ts,
        "action_badge": e.action,
        "action_label": _human_action_label(e.action),
        "model_raw": e.model,
        "model_label": _human_model_label(e.model),
        "object_pk": e.object_pk,
        "target_label": f"{_human_model_label(e.model)} #{e.object_pk}",
        "actor_label": (e.user.username if e.user else "System"),
        "ip": e.ip,
        "summary": e.summary,
    }


def _activity_for_object(*, org, model_cls, obj_id: int, limit: int = 20) -> list[dict]:
    model = f"{model_cls._meta.app_label}.{model_cls.__name__}"
    events = list(
        AuditEvent.objects.filter(organization_id=org.id, model=model, object_pk=str(obj_id))
        .select_related("user")
        .order_by("-ts")[:limit]
    )
    rows = []
    for e in events:
        rows.append(
            {
                "ts": e.ts,
                "action_badge": e.action,
                "action_label": _human_action_label(e.action),
                "actor_label": (e.user.username if e.user else "System"),
                "summary": e.summary,
            }
        )
    return rows


def _versions_for_object(*, org, obj, limit: int = 20) -> list[ObjectVersion]:
    ct = ContentType.objects.get_for_model(obj.__class__)
    model_key = f"{obj.__class__._meta.app_label}.{obj.__class__._meta.model_name}"
    supports_compare = model_key in {"docsapp.document", "docsapp.documenttemplate"}
    items = list(
        ObjectVersion.objects.filter(organization=org, content_type=ct, object_id=str(obj.pk))
        .select_related("created_by")
        .order_by("-created_at")[:limit]
    )
    # Offer a simple "Compare to previous" UX: each item can compare to the next older version.
    for i, v in enumerate(items):
        compare_to = items[i + 1].id if (i + 1) < len(items) else None
        setattr(v, "compare_to_id", compare_to)
        setattr(v, "compare_supported", supports_compare)
    return items


def _completion_profile(*, org, user, details: bool = True) -> dict:
    """
    IT Glue-ish "completion profile" scoring (MVP).

    We score common object types based on whether key fields are filled out.
    This is intentionally opinionated and will likely become configurable later.
    """

    can_admin = _is_org_admin(user, org) or getattr(user, "is_superuser", False)

    def pct(earned: int, total: int) -> int:
        if total <= 0:
            return 100
        return int(round((earned / float(total)) * 100.0))

    def visible_docs_qs():
        qs = Document.objects.filter(organization=org, archived_at__isnull=True)
        if not can_admin:
            qs = qs.filter(_visible_docs_q(user, org)).distinct()
        return qs

    def visible_passwords_qs():
        qs = PasswordEntry.objects.filter(organization=org, archived_at__isnull=True)
        if not can_admin:
            qs = qs.filter(_visible_passwords_q(user, org)).distinct()
        return qs

    out_types: list[dict] = []
    overall_earned = 0
    overall_total = 0

    def add_type(*, key: str, label: str, url: str, qs, rules: list[dict], examples_q: Q):
        nonlocal overall_earned, overall_total
        total_items = int(qs.count())
        fields_total = total_items * len(rules)
        fields_earned = 0
        missing = []
        for r in rules:
            missing_q = r["missing_q"]
            missing_count = int(qs.filter(missing_q).count())
            fields_earned += (total_items - missing_count)
            missing.append({"label": r["label"], "missing": missing_count})

        examples = []
        if details and total_items:
            for obj in list(qs.filter(examples_q).order_by("name")[:8]):
                try:
                    obj_url = _url_for_object_detail(obj)
                except Exception:
                    obj_url = url
                examples.append({"label": str(getattr(obj, "name", "") or getattr(obj, "title", "") or obj.pk), "url": obj_url})

        t = {
            "key": key,
            "label": label,
            "url": url,
            "items": total_items,
            "earned": int(fields_earned),
            "total": int(fields_total),
            "pct": pct(int(fields_earned), int(fields_total)),
            "missing": sorted(missing, key=lambda x: (-int(x["missing"]), str(x["label"]))),
            "examples": examples,
        }
        out_types.append(t)
        overall_earned += int(fields_earned)
        overall_total += int(fields_total)

    # Assets: encourage location + basic identification.
    assets_qs = Asset.objects.filter(organization=org, archived_at__isnull=True)
    add_type(
        key="assets",
        label="Assets",
        url=reverse("ui:assets_list"),
        qs=assets_qs,
        rules=[
            {"label": "Location", "missing_q": Q(location__isnull=True)},
            {"label": "Manufacturer", "missing_q": Q(manufacturer="")},
            {"label": "Model", "missing_q": Q(model="")},
            {"label": "Serial #", "missing_q": Q(serial_number="")},
        ],
        examples_q=Q(location__isnull=True) | Q(manufacturer="") | Q(model="") | Q(serial_number=""),
    )

    # Config items: at least a hostname or an IP, plus OS when known.
    cfg_qs = ConfigurationItem.objects.filter(organization=org, archived_at__isnull=True)
    add_type(
        key="config",
        label="Config Items",
        url=reverse("ui:config_items_list"),
        qs=cfg_qs,
        rules=[
            {"label": "Hostname or IP", "missing_q": Q(hostname="") & Q(primary_ip__isnull=True)},
            {"label": "Operating system", "missing_q": Q(operating_system="")},
        ],
        examples_q=(Q(hostname="") & Q(primary_ip__isnull=True)) | Q(operating_system=""),
    )

    # Documents: body + folder + non-draft review state (basic hygiene).
    docs_qs = visible_docs_qs()
    add_type(
        key="docs",
        label="Docs",
        url=reverse("ui:documents_list"),
        qs=docs_qs,
        rules=[
            {"label": "Body", "missing_q": Q(body="")},
            {"label": "Folder", "missing_q": Q(folder__isnull=True)},
            {"label": "Reviewed (not Draft)", "missing_q": Q(review_state=Document.REVIEW_DRAFT)},
        ],
        examples_q=Q(body="") | Q(folder__isnull=True) | Q(review_state=Document.REVIEW_DRAFT),
    )

    # Passwords: secret present + username + URL (where applicable).
    pws_qs = visible_passwords_qs()
    add_type(
        key="passwords",
        label="Passwords",
        url=reverse("ui:passwords_list"),
        qs=pws_qs,
        rules=[
            {"label": "Secret set", "missing_q": Q(password_ciphertext="")},
            {"label": "Username", "missing_q": Q(username="")},
            {"label": "URL", "missing_q": Q(url="")},
        ],
        examples_q=Q(password_ciphertext="") | Q(username="") | Q(url=""),
    )

    # Domains: registrar + DNS provider + expiry date.
    dom_qs = Domain.objects.filter(organization=org, archived_at__isnull=True)
    add_type(
        key="domains",
        label="Domains",
        url=reverse("ui:domains_list"),
        qs=dom_qs,
        rules=[
            {"label": "Registrar", "missing_q": Q(registrar="")},
            {"label": "DNS provider", "missing_q": Q(dns_provider="")},
            {"label": "Expires on", "missing_q": Q(expires_on__isnull=True)},
        ],
        examples_q=Q(registrar="") | Q(dns_provider="") | Q(expires_on__isnull=True),
    )

    # SSL certs: identity + issuer + expiry.
    cert_qs = SSLCertificate.objects.filter(organization=org, archived_at__isnull=True)
    add_type(
        key="ssl",
        label="SSL Certs",
        url=reverse("ui:sslcerts_list"),
        qs=cert_qs,
        rules=[
            {"label": "Common name", "missing_q": Q(common_name="")},
            {"label": "Issuer", "missing_q": Q(issuer="")},
            {"label": "Not after", "missing_q": Q(not_after__isnull=True)},
        ],
        examples_q=Q(common_name="") | Q(issuer="") | Q(not_after__isnull=True),
    )

    out_types.sort(key=lambda t: (int(t.get("pct", 0)), str(t.get("label") or "")))
    return {
        "overall_pct": pct(int(overall_earned), int(overall_total)),
        "overall_earned": int(overall_earned),
        "overall_total": int(overall_total),
        "types": out_types,
        "can_admin": bool(can_admin),
    }


def _safe_snapshot_fields(snapshot: dict) -> dict:
    """
    Hide obviously sensitive fields in snapshots (future-proofing).
    """

    if not isinstance(snapshot, dict):
        return {"model": "", "fields": {}, "m2m": {}, "hidden": []}
    model = str(snapshot.get("model") or "")
    fields = snapshot.get("fields") or {}
    m2m = snapshot.get("m2m") or {}
    if not isinstance(fields, dict):
        fields = {}
    if not isinstance(m2m, dict):
        m2m = {}

    hidden = []
    out_fields = {}
    for k, v in fields.items():
        key = str(k or "")
        lk = key.lower()
        if any(x in lk for x in ["ciphertext", "secret", "token", "private_key", "password"]):
            hidden.append(key)
            continue
        out_fields[key] = v

    return {"model": model, "fields": out_fields, "m2m": m2m, "hidden": hidden}


def _unified_text_diff(a: str, b: str, *, fromfile: str, tofile: str, max_lines: int = 500) -> str:
    a_lines = (a or "").splitlines(keepends=True)
    b_lines = (b or "").splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(a_lines, b_lines, fromfile=fromfile, tofile=tofile))
    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + [f"\n... diff truncated ({max_lines} lines shown) ...\n"]
    return "".join(diff_lines).strip()


def _version_diff_rows(*, org, model_key: str, newer: dict, older: dict) -> dict:
    """
    Return {scalars: [...], texts: [...], m2m: [...], hidden: [...]}
    """

    nf = newer.get("fields") or {}
    of = older.get("fields") or {}
    nm = newer.get("m2m") or {}
    om = older.get("m2m") or {}

    allow_fields = []
    text_fields = []
    allow_m2m = []

    if model_key == "docsapp.document":
        allow_fields = ["title", "visibility", "folder_id", "template_id", "archived_at", "flagged_at"]
        text_fields = ["body"]
        allow_m2m = ["tags", "allowed_users"]
    elif model_key == "docsapp.documenttemplate":
        allow_fields = ["name", "archived_at", "review_state"]
        text_fields = ["body"]
        allow_m2m = ["tags"]
    else:
        # Default to showing nothing rather than accidentally exposing fields.
        allow_fields = []
        text_fields = []
        allow_m2m = []

    def _id_label(field: str, raw):
        try:
            if raw in (None, "", 0, "0"):
                return None
            i = int(str(raw))
        except Exception:
            return str(raw)
        if model_key == "docsapp.document" and field == "folder_id":
            f = DocumentFolder.objects.filter(organization=org, id=i).first()
            return f.name if f else f"#{i}"
        if model_key == "docsapp.document" and field == "template_id":
            t = DocumentTemplate.objects.filter(organization=org, id=i).first()
            return t.name if t else f"#{i}"
        return f"#{i}"

    scalars = []
    for f in allow_fields:
        a = of.get(f)
        b = nf.get(f)
        if a == b:
            continue
        before = _id_label(f, a) if f.endswith("_id") else a
        after = _id_label(f, b) if f.endswith("_id") else b
        scalars.append({"field": f, "before": before, "after": after})

    texts = []
    for f in text_fields:
        a = str(of.get(f) or "")
        b = str(nf.get(f) or "")
        if a == b:
            continue
        diff = _unified_text_diff(a, b, fromfile=f"v{older.get('id') or 'old'}:{f}", tofile=f"v{newer.get('id') or 'new'}:{f}")
        texts.append({"field": f, "diff": diff})

    def _names_for_ids(kind: str, ids: list[int]) -> list[str]:
        ids = [int(x) for x in ids if isinstance(x, int) or str(x).isdigit()]
        if not ids:
            return []
        if kind == "tags":
            by_id = {t.id: t.name for t in Tag.objects.filter(Q(organization__isnull=True) | Q(organization=org)).filter(id__in=ids)}
            return [by_id.get(i, f"#{i}") for i in ids]
        if kind == "allowed_users":
            User = get_user_model()
            by_id = {u.id: u.username for u in User.objects.filter(id__in=ids)}
            return [by_id.get(i, f"#{i}") for i in ids]
        return [f"#{i}" for i in ids]

    m2m_rows = []
    for f in allow_m2m:
        a_ids = om.get(f) or []
        b_ids = nm.get(f) or []
        try:
            a_set = {int(x) for x in a_ids}
            b_set = {int(x) for x in b_ids}
        except Exception:
            continue
        if a_set == b_set:
            continue
        removed = sorted(a_set - b_set)
        added = sorted(b_set - a_set)
        m2m_rows.append(
            {
                "field": f,
                "added": _names_for_ids(f, added),
                "removed": _names_for_ids(f, removed),
            }
        )

    return {"scalars": scalars, "texts": texts, "m2m": m2m_rows}


def _confirm_delete(
    request: HttpRequest,
    *,
    org,
    kind: str,
    label: str,
    cancel_url: str,
    redirect_url: str,
    warning: str | None,
    verb: str = "Delete",
    sub: str | None = None,
    on_confirm,
):
    if request.method == "POST" and request.POST.get("confirm") == "1":
        on_confirm()
        return redirect(redirect_url)
    return render(
        request,
        "ui/delete_confirm.html",
        {
            "org": org,
            "kind": kind,
            "label": label,
            "cancel_url": cancel_url,
            "warning": warning,
            "verb": verb,
            "sub": sub,
        },
    )


@login_required
@require_POST
def version_restore(request: HttpRequest, version_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    v = get_object_or_404(ObjectVersion.objects.select_related("content_type"), organization=org, id=version_id)
    model_cls = v.content_type.model_class()
    if model_cls is None:
        raise PermissionDenied("Invalid version model.")
    # We only support restoring onto existing objects for now.
    obj = model_cls.objects.filter(pk=v.object_id).first()
    if obj is None:
        raise PermissionDenied("Object no longer exists (restore-from-delete not implemented yet).")
    obj_org_id = getattr(obj, "organization_id", None)
    if obj_org_id is not None and int(obj_org_id) != int(org.id):
        raise PermissionDenied("Object does not belong to current org.")

    restore_instance_from_snapshot(obj, v.snapshot or {})

    ObjectVersion.objects.create(
        organization=org,
        content_type=v.content_type,
        object_id=str(obj.pk),
        action=ObjectVersion.ACTION_RESTORE,
        created_by=request.user,
        summary=f"Restored from v{v.id}"[:255],
        snapshot=v.snapshot or {},
    )

    # Best-effort redirect to object detail.
    try:
        url = _url_for_object_detail(obj)
    except Exception:
        url = reverse("ui:dashboard")
    return _redirect_back(request, fallback_url=url)


@login_required
@require_POST
def object_restore(request: HttpRequest) -> HttpResponse:
    """
    Restore (un-archive) an org-scoped object by ref: "app_label.model:pk".
    """

    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    ref = (request.POST.get("ref") or "").strip()
    parsed = _parse_ref(ref)
    if not parsed:
        raise PermissionDenied("Invalid object ref.")
    ct, oid = parsed
    model_cls = ct.model_class()
    if model_cls is None:
        raise PermissionDenied("Invalid object model.")

    # Only support models with an `archived_at` field.
    if not hasattr(model_cls, "archived_at"):
        raise PermissionDenied("This object type cannot be restored.")

    obj = model_cls.objects.filter(pk=int(oid)).first()
    if obj is None:
        raise PermissionDenied("Object not found.")
    obj_org_id = getattr(obj, "organization_id", None)
    if obj_org_id is not None and int(obj_org_id) != int(org.id):
        raise PermissionDenied("Object does not belong to current org.")

    if getattr(obj, "archived_at", None) is not None:
        obj.archived_at = None
        obj.save(update_fields=["archived_at"])

    # Best-effort redirect to object detail.
    try:
        url = _url_for_object_detail(obj)
    except Exception:
        url = reverse("ui:dashboard")
    return _redirect_back(request, fallback_url=url)


@login_required
def home(request: HttpRequest) -> HttpResponse:
    # If an org is already selected, go to dashboard; otherwise show org picker.
    try:
        require_current_org(request)
        return redirect("ui:dashboard")
    except PermissionDenied:
        pass

    orgs = get_allowed_org_qs(request.user)
    next_url = (request.GET.get("next") or "").strip()
    next_qs = ""
    if next_url:
        next_qs = "?" + urlencode({"next": next_url})
    return render(request, "ui/org_select.html", {"orgs": orgs, "next_qs": next_qs})


@login_required
def enter_org(request: HttpRequest, org_id: int) -> HttpResponse:
    org = get_object_or_404(get_allowed_org_qs(request.user), id=org_id)
    set_current_org_id(request, org.id)
    _audit_event(
        request=request,
        org=org,
        action=AuditEvent.ACTION_UPDATE,
        model="security.OrgSession",
        object_pk=str(getattr(request.user, "id", "")),
        summary=f"Entered organization '{org.name}'.",
    )
    next_url = (request.GET.get("next") or "").strip()
    if next_url and next_url.startswith("/app/") and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        return redirect(next_url)
    return redirect("ui:dashboard")


@login_required
def account_view(request: HttpRequest) -> HttpResponse:
    """
    Account/profile settings that should be accessible even when no org is selected.
    """

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    default_org = profile.default_organization
    allowed_orgs = list(get_allowed_org_qs(request.user).order_by("name")[:500])

    # API token (personal).
    if request.method == "POST" and request.POST.get("_action") == "api_token_reveal":
        Token.objects.get_or_create(user=request.user)
        request.session["homeglue_show_api_token"] = True
        return redirect("ui:account")

    if request.method == "POST" and request.POST.get("_action") == "api_token_hide":
        request.session.pop("homeglue_show_api_token", None)
        return redirect("ui:account")

    if request.method == "POST" and request.POST.get("_action") == "api_token_rotate":
        Token.objects.filter(user=request.user).delete()
        tok = Token.objects.create(user=request.user)
        request.session["homeglue_show_api_token"] = True
        request.session["homeglue_new_api_token"] = tok.key
        return redirect("ui:account")

    # Default org.
    if request.method == "POST" and request.POST.get("_action") == "set_default_org":
        raw = (request.POST.get("default_org_id") or "").strip()
        if raw and raw.isdigit():
            o = get_allowed_org_qs(request.user).filter(id=int(raw)).first()
            profile.default_organization = o
        else:
            profile.default_organization = None
        profile.save(update_fields=["default_organization", "updated_at"])
        return redirect("ui:account")

    pw_changed = False
    pw_error = ""
    if request.method == "POST" and request.POST.get("_action") == "change_password":
        old_pw = request.POST.get("old_password") or ""
        new1 = request.POST.get("new_password1") or ""
        new2 = request.POST.get("new_password2") or ""
        if not request.user.check_password(old_pw):
            pw_error = "Current password is incorrect."
        elif not new1 or len(new1) < 8:
            pw_error = "New password must be at least 8 characters."
        elif new1 != new2:
            pw_error = "New passwords do not match."
        else:
            request.user.set_password(new1)
            request.user.save(update_fields=["password"])
            update_session_auth_hash(request, request.user)
            pw_changed = True

    api_tok = Token.objects.filter(user=request.user).first()
    show_api_tok = bool(request.session.get("homeglue_show_api_token"))
    new_api_tok = request.session.pop("homeglue_new_api_token", None)
    api_token_value = None
    if show_api_tok:
        if api_tok:
            api_token_value = api_tok.key
        else:
            api_tok = Token.objects.create(user=request.user)
            api_token_value = api_tok.key

    return render(
        request,
        "ui/account.html",
        {
            "org": org,
            "crumbs": _crumbs(("Account", None)),
            "default_org": default_org,
            "allowed_orgs": allowed_orgs,
            "api_token_exists": bool(api_tok),
            "api_token_value": api_token_value,
            "api_token_new_value": new_api_tok,
            "pw_changed": pw_changed,
            "pw_error": pw_error,
        },
    )


@login_required
def super_admin_home(request: HttpRequest) -> HttpResponse:
    """
    Superuser-only admin dashboard for initial setup and ongoing management.
    This intentionally avoids requiring the Django admin site.
    """

    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str, secret: str | None = None, secret_label: str | None = None):
        request.session["homeglue_flash"] = {"title": title, "body": body, "secret": secret, "secret_label": secret_label}

    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip()
        if action == "org_create":
            name = (request.POST.get("org_name") or "").strip()
            desc = (request.POST.get("org_description") or "").strip()
            add_me = (request.POST.get("org_add_me_owner") or "").strip() == "1"
            if not name:
                _set_flash(title="Org not created", body="Name is required.")
                return redirect("ui:super_admin_home")
            try:
                o = Organization.objects.create(name=name, description=desc)
                if add_me:
                    OrganizationMembership.objects.get_or_create(user=request.user, organization=o, defaults={"role": OrganizationMembership.ROLE_OWNER})
                _set_flash(title="Org created", body=f"Created '{o.name}'.")
            except IntegrityError:
                _set_flash(title="Org not created", body="An organization with that name already exists.")
            return redirect("ui:super_admin_home")

        if action == "user_create":
            username = (request.POST.get("username") or "").strip()
            email = (request.POST.get("email") or "").strip()
            pw = (request.POST.get("password") or "").strip()
            if not username:
                _set_flash(title="User not created", body="Username is required.")
                return redirect("ui:super_admin_home")
            User = get_user_model()
            if User.objects.filter(username=username).exists():
                _set_flash(title="User not created", body="That username already exists.")
                return redirect("ui:super_admin_home")
            if not pw:
                import secrets

                pw = secrets.token_urlsafe(12)
            u = User.objects.create_user(username=username, email=email or "", password=pw)
            _set_flash(title="User created", body=f"Created user '{u.username}'.", secret=pw, secret_label="Temp password")
            return redirect("ui:super_admin_home")

    orgs = list(
        Organization.objects.all()
        .order_by("name")[:500]
    )
    # Annotate member counts (bounded).
    by_org = {row["organization_id"]: int(row["c"]) for row in OrganizationMembership.objects.values("organization_id").annotate(c=Count("id"))}
    for o in orgs:
        setattr(o, "member_count", by_org.get(o.id, 0))

    User = get_user_model()
    users = list(User.objects.order_by("-id")[:12])

    return render(
        request,
        "ui/super_admin_home.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", None)),
            "flash": flash,
            "orgs": orgs,
            "users": users,
        },
    )


@login_required
def super_admin_setup(request: HttpRequest) -> HttpResponse:
    """
    Superuser-only first-time setup wizard.

    This is intentionally pragmatic: it guides the operator through the essential steps,
    while still allowing skipping to the normal admin pages.
    """

    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org_ctx = ctx.organization if ctx else None

    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str, secret: str | None = None, secret_label: str | None = None):
        request.session["homeglue_flash"] = {"title": title, "body": body, "secret": secret, "secret_label": secret_label}

    try:
        step = int((request.GET.get("step") or "1").strip())
    except Exception:
        step = 1
    step = max(1, min(5, int(step)))

    orgs = list(Organization.objects.all().order_by("name")[:500])
    selected_org_id = request.session.get("homeglue_setup_org_id")
    if request.GET.get("org_id") and str(request.GET.get("org_id") or "").isdigit():
        selected_org_id = int(str(request.GET.get("org_id")))
        request.session["homeglue_setup_org_id"] = int(selected_org_id)
    selected_org = Organization.objects.filter(id=selected_org_id).first() if selected_org_id else None

    # Preload/ensure system settings row.
    from apps.core.models import SystemSettings

    sys_obj = SystemSettings.objects.first()
    if sys_obj is None:
        sys_obj = SystemSettings.objects.create()

    # Forms used in some steps
    from apps.ui.forms import ProxmoxConnectionForm, SystemEmailSettingsForm
    from apps.integrations.models import ProxmoxConnection

    prox_form = None
    email_form = None

    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip().lower()

        if action == "reset":
            request.session.pop("homeglue_setup_org_id", None)
            _set_flash(title="Reset", body="Wizard state cleared.")
            return redirect(reverse("ui:super_admin_setup") + "?step=1")

        if action == "org_select":
            raw = (request.POST.get("org_id") or "").strip()
            if raw.isdigit():
                selected_org = Organization.objects.filter(id=int(raw)).first()
                if selected_org:
                    request.session["homeglue_setup_org_id"] = int(selected_org.id)
                    return redirect(reverse("ui:super_admin_setup") + "?step=2")
            _set_flash(title="Not selected", body="Pick an existing organization.")
            return redirect(reverse("ui:super_admin_setup") + "?step=1")

        if action == "org_create":
            name = (request.POST.get("org_name") or "").strip()
            desc = (request.POST.get("org_description") or "").strip()
            add_me = (request.POST.get("org_add_me_owner") or "").strip() == "1"
            if not name:
                _set_flash(title="Org not created", body="Name is required.")
                return redirect(reverse("ui:super_admin_setup") + "?step=1")
            try:
                o = Organization.objects.create(name=name, description=desc)
                if add_me:
                    OrganizationMembership.objects.get_or_create(user=request.user, organization=o, defaults={"role": OrganizationMembership.ROLE_OWNER})
                request.session["homeglue_setup_org_id"] = int(o.id)
                _set_flash(title="Org created", body=f"Created '{o.name}'.")
                return redirect(reverse("ui:super_admin_setup") + "?step=2")
            except IntegrityError:
                _set_flash(title="Org not created", body="An organization with that name already exists.")
                return redirect(reverse("ui:super_admin_setup") + "?step=1")

        if action == "user_create":
            if not selected_org:
                _set_flash(title="No org selected", body="Select or create an organization first.")
                return redirect(reverse("ui:super_admin_setup") + "?step=1")
            username = (request.POST.get("username") or "").strip()
            email = (request.POST.get("email") or "").strip()
            pw = (request.POST.get("password") or "").strip()
            role = (request.POST.get("role") or OrganizationMembership.ROLE_MEMBER).strip()
            role = role if role in {OrganizationMembership.ROLE_MEMBER, OrganizationMembership.ROLE_ADMIN, OrganizationMembership.ROLE_OWNER} else OrganizationMembership.ROLE_MEMBER
            if not username:
                _set_flash(title="User not created", body="Username is required.")
                return redirect(reverse("ui:super_admin_setup") + "?step=2")
            User = get_user_model()
            if User.objects.filter(username=username).exists():
                _set_flash(title="User not created", body="That username already exists.")
                return redirect(reverse("ui:super_admin_setup") + "?step=2")
            if not pw:
                import secrets

                pw = secrets.token_urlsafe(12)
            u = User.objects.create_user(username=username, email=email or "", password=pw)
            OrganizationMembership.objects.create(organization=selected_org, user=u, role=role)
            _set_flash(title="User created", body=f"Created '{u.username}' and added to '{selected_org.name}'.", secret=pw, secret_label="Temp password")
            return redirect(reverse("ui:super_admin_setup") + "?step=2")

        if action == "system_save":
            base_url = (request.POST.get("base_url") or "").strip().rstrip("/")
            ip_allowlist = (request.POST.get("ip_allowlist") or "").strip()
            ip_blocklist = (request.POST.get("ip_blocklist") or "").strip()
            trust = (request.POST.get("trust_x_forwarded_for") or "").strip() == "1"
            proxies = (request.POST.get("trusted_proxy_cidrs") or "").strip()
            cors_allowed_origins = (request.POST.get("cors_allowed_origins") or "").strip()
            csrf_trusted_origins = (request.POST.get("csrf_trusted_origins") or "").strip()
            allowed_hosts = (request.POST.get("allowed_hosts") or "").strip()
            sys_obj.base_url = base_url
            sys_obj.ip_allowlist = ip_allowlist
            sys_obj.ip_blocklist = ip_blocklist
            sys_obj.trust_x_forwarded_for = trust
            sys_obj.trusted_proxy_cidrs = proxies
            sys_obj.cors_allowed_origins = cors_allowed_origins
            sys_obj.csrf_trusted_origins = csrf_trusted_origins
            sys_obj.allowed_hosts = allowed_hosts
            sys_obj.save()
            _set_flash(title="Saved", body="System settings saved.")
            return redirect(reverse("ui:super_admin_setup") + "?step=3")

        if action == "email_save":
            email_form = SystemEmailSettingsForm(request.POST)
            if email_form.is_valid():
                from apps.secretsapp.crypto import encrypt_str, HomeGlueCryptoError

                sys_obj.email_source = email_form.cleaned_data["email_source"]
                sys_obj.email_enabled = bool(email_form.cleaned_data.get("email_enabled"))
                sys_obj.email_backend = str(email_form.cleaned_data.get("email_backend") or "console").strip().lower()
                sys_obj.email_from = str(email_form.cleaned_data.get("email_from") or "").strip()
                sys_obj.smtp_host = str(email_form.cleaned_data.get("smtp_host") or "").strip()
                sys_obj.smtp_port = int(email_form.cleaned_data.get("smtp_port") or 587)
                sys_obj.smtp_user = str(email_form.cleaned_data.get("smtp_user") or "").strip()
                sys_obj.smtp_use_tls = bool(email_form.cleaned_data.get("smtp_use_tls"))
                sys_obj.smtp_use_ssl = bool(email_form.cleaned_data.get("smtp_use_ssl"))
                clear_pw = bool(email_form.cleaned_data.get("smtp_password_clear"))
                new_pw = (email_form.cleaned_data.get("smtp_password") or "").strip()
                try:
                    if clear_pw:
                        sys_obj.smtp_password_ciphertext = ""
                    elif new_pw:
                        sys_obj.smtp_password_ciphertext = encrypt_str(new_pw)
                except HomeGlueCryptoError as e:
                    _set_flash(title="Not saved", body=str(e))
                    return redirect(reverse("ui:super_admin_setup") + "?step=4")
                sys_obj.save()
                _set_flash(title="Saved", body="Email settings saved.")
                return redirect(reverse("ui:super_admin_setup") + "?step=4")

        if action == "proxmox_add":
            if not selected_org:
                _set_flash(title="No org selected", body="Select or create an organization first.")
                return redirect(reverse("ui:super_admin_setup") + "?step=1")
            prox_form = ProxmoxConnectionForm(request.POST, org=selected_org)
            if prox_form.is_valid():
                obj = prox_form.save(commit=False)
                obj.organization = selected_org
                obj.save()
                _set_flash(title="Saved", body="Proxmox connection created. You can sync from Admin -> Operations.")
                return redirect(reverse("ui:super_admin_setup") + "?step=5")
            # fall through to render with errors

        if action == "finish":
            if not selected_org:
                _set_flash(title="No org selected", body="Select or create an organization first.")
                return redirect(reverse("ui:super_admin_setup") + "?step=1")
            # Set org in session so user lands inside the org.
            set_current_org_id(request, selected_org.id)
            # Mark instance as having completed first-time setup.
            from django.utils import timezone

            if getattr(sys_obj, "setup_completed_at", None) is None:
                sys_obj.setup_completed_at = timezone.now()
                sys_obj.save(update_fields=["setup_completed_at", "updated_at"])
            request.session.pop("homeglue_setup_org_id", None)
            _set_flash(title="Setup complete", body=f"Entered organization '{selected_org.name}'.")
            return redirect("ui:dashboard")

    # GET / fallthrough forms
    if email_form is None:
        email_init = {
            "email_source": getattr(sys_obj, "email_source", "env") or "env",
            "email_enabled": bool(getattr(sys_obj, "email_enabled", False)),
            "email_backend": (getattr(sys_obj, "email_backend", "") or "console").strip().lower(),
            "email_from": (getattr(sys_obj, "email_from", "") or "").strip(),
            "smtp_host": (getattr(sys_obj, "smtp_host", "") or "").strip(),
            "smtp_port": int(getattr(sys_obj, "smtp_port", 587) or 587),
            "smtp_user": (getattr(sys_obj, "smtp_user", "") or "").strip(),
            "smtp_use_tls": bool(getattr(sys_obj, "smtp_use_tls", True)),
            "smtp_use_ssl": bool(getattr(sys_obj, "smtp_use_ssl", False)),
        }
        email_form = SystemEmailSettingsForm(initial=email_init)
    if prox_form is None and selected_org is not None:
        prox_form = ProxmoxConnectionForm(org=selected_org)
    existing_prox = list(ProxmoxConnection.objects.filter(organization=selected_org).order_by("name")[:50]) if selected_org else []

    steps = [
        {"n": 1, "title": "Org"},
        {"n": 2, "title": "Users"},
        {"n": 3, "title": "System"},
        {"n": 4, "title": "Email"},
        {"n": 5, "title": "Integrations"},
    ]

    return render(
        request,
        "ui/super_admin_setup.html",
        {
            "org": org_ctx,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Setup wizard", None)),
            "flash": flash,
            "step": step,
            "steps": steps,
            "orgs": orgs,
            "selected_org": selected_org,
            "sys_obj": sys_obj,
            "email_form": email_form,
            "pw_set": bool((sys_obj.smtp_password_ciphertext or "").strip()),
            "proxmox_form": prox_form,
            "existing_prox": existing_prox,
        },
    )


@login_required
def super_admin_config_status(request: HttpRequest) -> HttpResponse:
    """
    Superuser-only view of env-backed configuration, plus basic config tests.

    Notes:
    - Secrets are never displayed in full.
    - For most settings, changes are applied by editing `.env` and recreating containers.
    """

    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str):
        request.session["homeglue_flash"] = {"title": title, "body": body}

    def _mask(s: str, *, keep: int = 3) -> str:
        s = (s or "").strip()
        if not s:
            return ""
        if len(s) <= (keep * 2):
            return "*" * len(s)
        return f"{s[:keep]}...{s[-keep:]}"

    # Email / notifications (env-backed)
    email_enabled = bool(getattr(settings, "HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED", False))
    email_backend = str(getattr(settings, "HOMEGLUE_EMAIL_BACKEND", "") or "").strip().lower()
    default_from = str(getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
    smtp_host = str(getattr(settings, "EMAIL_HOST", "") or "").strip()
    smtp_port = getattr(settings, "EMAIL_PORT", "")
    smtp_user = str(getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
    smtp_tls = bool(getattr(settings, "EMAIL_USE_TLS", False))
    smtp_ssl = bool(getattr(settings, "EMAIL_USE_SSL", False))
    email_ready = (not email_enabled) or (email_backend in {"smtp", "smtp+tls", "smtp+ssl"} and bool(smtp_host))

    # OIDC SSO (env-backed)
    oidc_enabled = bool(getattr(settings, "HOMEGLUE_OIDC_ENABLED", False))
    oidc_client_id = str(getattr(settings, "OIDC_RP_CLIENT_ID", "") or "").strip()
    oidc_client_secret = str(getattr(settings, "OIDC_RP_CLIENT_SECRET", "") or "").strip()
    oidc_auth = str(getattr(settings, "OIDC_OP_AUTHORIZATION_ENDPOINT", "") or "").strip()
    oidc_token = str(getattr(settings, "OIDC_OP_TOKEN_ENDPOINT", "") or "").strip()
    oidc_user = str(getattr(settings, "OIDC_OP_USER_ENDPOINT", "") or "").strip()
    oidc_jwks = str(getattr(settings, "OIDC_OP_JWKS_ENDPOINT", "") or "").strip()
    oidc_sign_algo = str(getattr(settings, "OIDC_RP_SIGN_ALGO", "") or "").strip()
    oidc_scopes = getattr(settings, "OIDC_RP_SCOPES", [])
    oidc_ready = (not oidc_enabled) or (bool(oidc_client_id) and bool(oidc_client_secret) and bool(oidc_auth) and bool(oidc_token))

    # Security / secrets (presence only)
    secret_key_set = bool(str(getattr(settings, "SECRET_KEY", "") or "").strip())
    fernet_key_set = bool(str(getattr(settings, "HOMEGLUE_FERNET_KEY", "") or "").strip())
    base_url_env = str(getattr(settings, "HOMEGLUE_BASE_URL", "") or "").strip().rstrip("/")

    # Host/CORS
    allowed_hosts = list(getattr(settings, "ALLOWED_HOSTS", []) or [])
    # Note: CORS/CSRF can be DB-overridden via DynamicDbSettingsMiddleware.
    cors_allowed_origins = list(getattr(settings, "CORS_ALLOWED_ORIGINS", []) or [])
    csrf_trusted_origins = list(getattr(settings, "CSRF_TRUSTED_ORIGINS", []) or [])

    if request.method == "POST" and request.POST.get("_action") == "send_test_email":
        to_addr = (request.POST.get("to") or "").strip()
        if not to_addr:
            to_addr = (getattr(request.user, "email", "") or "").strip()
        if not to_addr:
            _set_flash(title="Not sent", body="No email address provided (and your user has no email set).")
            return redirect("ui:super_admin_config_status")
        try:
            from django.core.mail import send_mail

            send_mail(
                subject="HomeGlue test email",
                message="This is a test email from HomeGlue.\n\nIf you received this, SMTP delivery is working.",
                from_email=default_from or None,
                recipient_list=[to_addr],
                fail_silently=False,
            )
            _set_flash(title="Sent", body=f"Test email queued/sent to {to_addr}. Check your SMTP logs/inbox.")
        except Exception as e:
            _set_flash(title="Not sent", body=f"Email delivery failed: {e}")
        return redirect("ui:super_admin_config_status")

    return render(
        request,
        "ui/super_admin_config_status.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Config & status", None)),
            "flash": flash,
            "email": {
                "enabled": email_enabled,
                "backend": email_backend,
                "default_from": default_from,
                "smtp_host": smtp_host,
                "smtp_port": smtp_port,
                "smtp_user": smtp_user,
                "smtp_user_masked": _mask(smtp_user),
                "smtp_tls": smtp_tls,
                "smtp_ssl": smtp_ssl,
                "ready": email_ready,
            },
            "oidc": {
                "enabled": oidc_enabled,
                "client_id": oidc_client_id,
                "client_secret_set": bool(oidc_client_secret),
                "client_secret_masked": _mask(oidc_client_secret),
                "auth_endpoint": oidc_auth,
                "token_endpoint": oidc_token,
                "user_endpoint": oidc_user,
                "jwks_endpoint": oidc_jwks,
                "sign_algo": oidc_sign_algo,
                "scopes": oidc_scopes,
                "ready": oidc_ready,
            },
            "security": {
                "secret_key_set": secret_key_set,
                "fernet_key_set": fernet_key_set,
                "base_url_env": base_url_env,
                "base_url_effective": get_base_url(),
            },
            "hosts": {"allowed_hosts": allowed_hosts, "cors_allowed_origins": cors_allowed_origins, "csrf_trusted_origins": csrf_trusted_origins},
        },
    )


@login_required
def super_admin_sso(request: HttpRequest) -> HttpResponse:
    """
    Superuser-only view of SSO/OIDC configuration.

    OIDC remains env-backed (restart required) because it affects auth backends and URL routing.
    """

    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    def _mask(s: str, *, keep: int = 3) -> str:
        s = (s or "").strip()
        if not s:
            return ""
        if len(s) <= (keep * 2):
            return "*" * len(s)
        return f"{s[:keep]}...{s[-keep:]}"

    oidc_enabled = bool(getattr(settings, "HOMEGLUE_OIDC_ENABLED", False))
    cfg = {
        "enabled": oidc_enabled,
        "client_id": str(getattr(settings, "OIDC_RP_CLIENT_ID", "") or "").strip(),
        "client_secret_set": bool(str(getattr(settings, "OIDC_RP_CLIENT_SECRET", "") or "").strip()),
        "client_secret_masked": _mask(str(getattr(settings, "OIDC_RP_CLIENT_SECRET", "") or "")),
        "auth_endpoint": str(getattr(settings, "OIDC_OP_AUTHORIZATION_ENDPOINT", "") or "").strip(),
        "token_endpoint": str(getattr(settings, "OIDC_OP_TOKEN_ENDPOINT", "") or "").strip(),
        "user_endpoint": str(getattr(settings, "OIDC_OP_USER_ENDPOINT", "") or "").strip(),
        "jwks_endpoint": str(getattr(settings, "OIDC_OP_JWKS_ENDPOINT", "") or "").strip(),
        "sign_algo": str(getattr(settings, "OIDC_RP_SIGN_ALGO", "") or "").strip(),
        "scopes": getattr(settings, "OIDC_RP_SCOPES", []) or [],
    }

    env_snippet = "\n".join(
        [
            "HOMEGLUE_OIDC_ENABLED=true",
            "HOMEGLUE_OIDC_CLIENT_ID=...",
            "HOMEGLUE_OIDC_CLIENT_SECRET=...",
            "HOMEGLUE_OIDC_AUTHORIZATION_ENDPOINT=https://idp.example.com/oauth2/v1/authorize",
            "HOMEGLUE_OIDC_TOKEN_ENDPOINT=https://idp.example.com/oauth2/v1/token",
            "HOMEGLUE_OIDC_USER_ENDPOINT=https://idp.example.com/oauth2/v1/userinfo",
            "HOMEGLUE_OIDC_JWKS_ENDPOINT=https://idp.example.com/oauth2/v1/keys",
            "HOMEGLUE_OIDC_SIGN_ALGO=RS256",
            "HOMEGLUE_OIDC_SCOPES=openid email profile",
        ]
    )

    return render(
        request,
        "ui/super_admin_sso.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("SSO (OIDC)", None)),
            "oidc": cfg,
            "env_snippet": env_snippet,
        },
    )


@login_required
def super_admin_email_settings(request: HttpRequest) -> HttpResponse:
    """
    Superuser-only UI to configure DB-backed email settings.

    This stores the SMTP password encrypted using HOMEGLUE_FERNET_KEY.
    """

    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str):
        request.session["homeglue_flash"] = {"title": title, "body": body}

    error = ""
    try:
        from django.core.mail import EmailMessage, send_mail

        from apps.core.models import SystemSettings
        from apps.core.system_settings import get_email_settings
        from apps.secretsapp.crypto import HomeGlueCryptoError, encrypt_str
        from apps.ui.forms import SystemEmailSettingsForm
    except Exception as e:
        return render(
            request,
            "ui/super_admin_email_settings.html",
            {
                "org": org,
                "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Email settings", None)),
                "flash": flash,
                "form": None,
                "error": f"Unable to load dependencies: {e}",
                "pw_set": False,
            },
        )

    obj = SystemSettings.objects.first()
    if obj is None:
        obj = SystemSettings.objects.create()
    pw_set = bool((obj.smtp_password_ciphertext or "").strip())

    if request.method == "POST":
        form = SystemEmailSettingsForm(request.POST)
        if form.is_valid():
            action = (request.POST.get("_action") or "save").strip().lower()

            obj.email_source = form.cleaned_data["email_source"]
            obj.email_enabled = bool(form.cleaned_data.get("email_enabled"))
            obj.email_backend = str(form.cleaned_data.get("email_backend") or "console").strip().lower()
            obj.email_from = str(form.cleaned_data.get("email_from") or "").strip()
            obj.smtp_host = str(form.cleaned_data.get("smtp_host") or "").strip()
            obj.smtp_port = int(form.cleaned_data.get("smtp_port") or 587)
            obj.smtp_user = str(form.cleaned_data.get("smtp_user") or "").strip()
            obj.smtp_use_tls = bool(form.cleaned_data.get("smtp_use_tls"))
            obj.smtp_use_ssl = bool(form.cleaned_data.get("smtp_use_ssl"))

            clear_pw = bool(form.cleaned_data.get("smtp_password_clear"))
            new_pw = (form.cleaned_data.get("smtp_password") or "").strip()
            if clear_pw:
                obj.smtp_password_ciphertext = ""
            elif new_pw:
                try:
                    obj.smtp_password_ciphertext = encrypt_str(new_pw)
                except HomeGlueCryptoError as e:
                    error = str(e)

            if error:
                _set_flash(title="Not saved", body=error)
                return redirect("ui:super_admin_email_settings")

            obj.save()
            pw_set = bool((obj.smtp_password_ciphertext or "").strip())
            _audit_event(
                request=request,
                org=None,
                action=AuditEvent.ACTION_UPDATE,
                model="system.SystemSettings",
                object_pk=str(obj.id),
                summary="Updated system email settings.",
            )

            if action == "send_test_email":
                to_addr = (request.POST.get("to") or "").strip() or (getattr(request.user, "email", "") or "").strip()
                if not to_addr:
                    _set_flash(title="Not sent", body="No email address provided (and your user has no email set).")
                    return redirect("ui:super_admin_email_settings")

                cfg = get_email_settings()
                if not bool(cfg.get("enabled")):
                    _set_flash(title="Not sent", body="Email is disabled. Enable email first.")
                    return redirect("ui:super_admin_email_settings")

                subject = "HomeGlue test email"
                message = "This is a test email from HomeGlue.\n\nIf you received this, SMTP delivery is working."
                from_email = (cfg.get("from_email") or "").strip() or None

                try:
                    if cfg.get("source") == "db":
                        backend = str(cfg.get("backend") or "console").strip().lower()
                        if backend == "console":
                            from django.core.mail.backends.console import EmailBackend as ConsoleBackend

                            conn = ConsoleBackend(fail_silently=False)
                        else:
                            from django.core.mail.backends.smtp import EmailBackend as SmtpBackend

                            use_tls = bool(cfg.get("smtp_use_tls")) and backend in {"smtp", "smtp+tls"}
                            use_ssl = bool(cfg.get("smtp_use_ssl")) or backend == "smtp+ssl"
                            conn = SmtpBackend(
                                host=str(cfg.get("smtp_host") or ""),
                                port=int(cfg.get("smtp_port") or 587),
                                username=str(cfg.get("smtp_user") or ""),
                                password=str(cfg.get("smtp_password") or ""),
                                use_tls=use_tls,
                                use_ssl=use_ssl,
                                timeout=int(getattr(settings, "HOMEGLUE_SMTP_TIMEOUT_SECONDS", 10) or 10),
                                fail_silently=False,
                            )
                        m = EmailMessage(subject=subject, body=message, from_email=from_email, to=[to_addr], connection=conn)
                        m.send(fail_silently=False)
                    else:
                        send_mail(subject=subject, message=message, from_email=from_email, recipient_list=[to_addr], fail_silently=False)
                    _set_flash(title="Sent", body=f"Test email queued/sent to {to_addr}. Check your SMTP logs/inbox.")
                except Exception as e:
                    _set_flash(title="Not sent", body=f"Email delivery failed: {e}")
                return redirect("ui:super_admin_email_settings")

            _set_flash(title="Saved", body="Email settings saved.")
            return redirect("ui:super_admin_email_settings")
    else:
        init = {
            "email_source": getattr(obj, "email_source", "env") or "env",
            "email_enabled": bool(getattr(obj, "email_enabled", False)),
            "email_backend": (getattr(obj, "email_backend", "") or "console").strip().lower(),
            "email_from": (getattr(obj, "email_from", "") or "").strip(),
            "smtp_host": (getattr(obj, "smtp_host", "") or "").strip(),
            "smtp_port": int(getattr(obj, "smtp_port", 587) or 587),
            "smtp_user": (getattr(obj, "smtp_user", "") or "").strip(),
            "smtp_use_tls": bool(getattr(obj, "smtp_use_tls", True)),
            "smtp_use_ssl": bool(getattr(obj, "smtp_use_ssl", False)),
        }
        form = SystemEmailSettingsForm(initial=init)

    return render(
        request,
        "ui/super_admin_email_settings.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Email settings", None)),
            "flash": flash,
            "form": form,
            "error": error,
            "pw_set": pw_set,
        },
    )


@login_required
def super_admin_operations(request: HttpRequest) -> HttpResponse:
    """
    Superuser-only operational tools and health for the instance.

    This is intentionally scoped:
    - Defaults to per-org operations (user must pick an org to avoid "combined org" views).
    - Includes a few safe global ops (like seeding rules) behind an explicit toggle.
    """

    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org_ctx = ctx.organization if ctx else None

    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str):
        request.session["homeglue_flash"] = {"title": title, "body": body}

    is_reauthed = _is_reauthed(request)
    next_url = request.get_full_path()
    reauth_url = f"{reverse('ui:reauth')}?{urlencode({'next': next_url})}"

    # Org selector (explicit, to preserve "org-first" mental model even for ops).
    orgs = list(Organization.objects.all().order_by("name")[:500])
    raw_org_id = (request.GET.get("org_id") or request.POST.get("org_id") or "").strip()
    selected_org = None
    if raw_org_id.isdigit():
        selected_org = Organization.objects.filter(id=int(raw_org_id)).first()

    # Heartbeat (instance-level)
    hb = None
    try:
        from apps.core.models import WorkerHeartbeat

        hb = WorkerHeartbeat.objects.filter(key="default").first()
    except Exception:
        hb = None

    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip()
        allow_all = (request.POST.get("allow_all_orgs") or "").strip() == "1"

        from django.core.management import call_command

        # Most operations are per-org to avoid accidental cross-org actions.
        if action in {"sync_proxmox", "run_workflows", "deliver_notifications", "run_checklist_schedules", "schedule_backups", "audit_policy_save", "audit_purge_now"}:
            if not selected_org:
                _set_flash(title="Not run", body="Pick an organization first.")
                return redirect(f"{reverse('ui:super_admin_operations')}?{urlencode({'org_id': raw_org_id})}" if raw_org_id else reverse("ui:super_admin_operations"))

        try:
            if action == "seed_workflow_rules":
                if selected_org:
                    call_command("seed_workflow_rules", org_id=int(selected_org.id))
                    _set_flash(title="Done", body=f"Seeded workflow rules for org '{selected_org.name}'.")
                    _audit_event(
                        request=request,
                        org=selected_org,
                        action=AuditEvent.ACTION_UPDATE,
                        model="ops.WorkflowSeed",
                        object_pk=str(selected_org.id),
                        summary="Seeded default workflow rules (admin operation).",
                    )
                else:
                    if not allow_all:
                        _set_flash(title="Not run", body="To seed rules for ALL orgs, check the confirmation box.")
                        return redirect(reverse("ui:super_admin_operations"))
                    call_command("seed_workflow_rules")
                    _set_flash(title="Done", body="Seeded workflow rules for ALL orgs.")
                    _audit_event(
                        request=request,
                        org=None,
                        action=AuditEvent.ACTION_UPDATE,
                        model="ops.WorkflowSeed",
                        object_pk="ALL",
                        summary="Seeded default workflow rules for ALL orgs (admin operation).",
                    )
                return redirect(reverse("ui:super_admin_operations") + (f"?{urlencode({'org_id': selected_org.id})}" if selected_org else ""))

            if action == "sync_proxmox":
                conn_id = (request.POST.get("connection_id") or "").strip()
                if conn_id and conn_id.isdigit():
                    call_command("sync_proxmox", org_id=int(selected_org.id), connection_id=int(conn_id))
                    _set_flash(title="Done", body="Proxmox sync completed for the selected connection.")
                    _audit_event(
                        request=request,
                        org=selected_org,
                        action=AuditEvent.ACTION_UPDATE,
                        model="ops.ProxmoxSync",
                        object_pk=str(int(conn_id)),
                        summary=f"Triggered Proxmox sync for connection_id={int(conn_id)} (admin operation).",
                    )
                else:
                    call_command("sync_proxmox", org_id=int(selected_org.id))
                    _set_flash(title="Done", body="Proxmox sync completed for the selected org.")
                    _audit_event(
                        request=request,
                        org=selected_org,
                        action=AuditEvent.ACTION_UPDATE,
                        model="ops.ProxmoxSync",
                        object_pk="ALL",
                        summary="Triggered Proxmox sync for all enabled connections in org (admin operation).",
                    )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

            if action == "run_checklist_schedules":
                call_command("run_checklist_schedules_once", org_id=int(selected_org.id))
                _set_flash(title="Done", body="Processed due checklist schedules for the selected org.")
                _audit_event(
                    request=request,
                    org=selected_org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="ops.ChecklistSchedules",
                    object_pk=str(selected_org.id),
                    summary="Processed due checklist schedules (admin operation).",
                )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

            if action == "run_workflows":
                call_command("run_workflows_once", org_id=int(selected_org.id))
                _set_flash(title="Done", body="Evaluated due workflow rules for the selected org.")
                _audit_event(
                    request=request,
                    org=selected_org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="ops.WorkflowsRun",
                    object_pk=str(selected_org.id),
                    summary="Evaluated due workflow rules (admin operation).",
                )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

            if action == "deliver_notifications":
                call_command("deliver_workflow_notifications_once", org_id=int(selected_org.id))
                _set_flash(title="Done", body="Attempted delivery of workflow notifications for the selected org.")
                _audit_event(
                    request=request,
                    org=selected_org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="ops.NotificationsDeliver",
                    object_pk=str(selected_org.id),
                    summary="Attempted workflow notification delivery (admin operation).",
                )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

            if action == "schedule_backups":
                call_command("run_backup_scheduler_once", org_id=int(selected_org.id), force=True)
                _set_flash(title="Done", body="Backup scheduler ran (force) for the selected org. Pending snapshots will be built by the worker.")
                _audit_event(
                    request=request,
                    org=selected_org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="ops.BackupScheduler",
                    object_pk=str(selected_org.id),
                    summary="Triggered backup scheduler (force) (admin operation).",
                )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

            if action == "audit_policy_save":
                if not _is_reauthed(request):
                    _set_flash(title="Not saved", body="Re-authentication required for audit governance changes.")
                    return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")
                from apps.audit.models import AuditPolicy

                policy, _ = AuditPolicy.objects.get_or_create(organization=selected_org)
                enabled = (request.POST.get("enabled") or "").strip() == "1"
                try:
                    retention_days = int((request.POST.get("retention_days") or "").strip() or policy.retention_days)
                except Exception:
                    retention_days = int(policy.retention_days or 365)
                retention_days = max(7, min(3650, retention_days))
                policy.enabled = bool(enabled)
                policy.retention_days = int(retention_days)
                policy.save(update_fields=["enabled", "retention_days", "updated_at"])
                _set_flash(title="Saved", body="Audit retention policy updated.")
                _audit_event(
                    request=request,
                    org=selected_org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="audit.AuditPolicy",
                    object_pk=str(selected_org.id),
                    summary=f"Updated audit policy: enabled={int(enabled)}, retention_days={int(retention_days)}.",
                )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

            if action == "audit_purge_now":
                if not _is_reauthed(request):
                    _set_flash(title="Not purged", body="Re-authentication required for audit purge.")
                    return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")
                from apps.audit.models import AuditPolicy
                from django.utils import timezone
                from datetime import timedelta

                policy, _ = AuditPolicy.objects.get_or_create(organization=selected_org)
                if not policy.enabled:
                    _set_flash(title="Not purged", body="Retention policy is disabled for this org.")
                    return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")
                try:
                    retention_days = int(policy.retention_days or 365)
                except Exception:
                    retention_days = 365
                retention_days = max(1, min(3650, retention_days))
                cutoff = timezone.now() - timedelta(days=retention_days)
                purged, _ = AuditEvent.objects.filter(organization=selected_org, ts__lt=cutoff).delete()
                _set_flash(title="Purged", body=f"Removed {int(purged)} audit event(s) older than {retention_days} days.")
                _audit_event(
                    request=request,
                    org=selected_org,
                    action=AuditEvent.ACTION_DELETE,
                    model="audit.AuditEvent",
                    object_pk="retention",
                    summary=f"Audit purge executed via Operations; removed {int(purged)} event(s).",
                )
                return redirect(reverse("ui:super_admin_operations") + f"?{urlencode({'org_id': selected_org.id})}")

        except Exception as e:
            _set_flash(title="Failed", body=str(e))
            return redirect(reverse("ui:super_admin_operations") + (f"?{urlencode({'org_id': selected_org.id})}" if selected_org else ""))

    # Org-scoped status (only when org is selected)
    org_status = None
    if selected_org:
        from apps.backups.models import BackupSnapshot
        from apps.audit.models import AuditPolicy
        from apps.integrations.models import ProxmoxConnection
        from apps.workflows.models import Notification, WorkflowRule, NotificationDeliveryAttempt
        from django.utils import timezone
        from datetime import timedelta

        pending_backups = BackupSnapshot.objects.filter(organization=selected_org, status__in=[BackupSnapshot.STATUS_PENDING, BackupSnapshot.STATUS_RUNNING]).count()
        failed_backups_7d = BackupSnapshot.objects.filter(organization=selected_org, status=BackupSnapshot.STATUS_FAILED).order_by("-created_at")[:10]
        recent_backups = list(BackupSnapshot.objects.filter(organization=selected_org).order_by("-created_at")[:12])
        prox_conns = list(ProxmoxConnection.objects.filter(organization=selected_org).order_by("name", "id")[:50])
        unread_notifications = Notification.objects.filter(organization=selected_org, read_at__isnull=True).count()

        since = timezone.now() - timedelta(days=1)
        failed_deliveries_24h = NotificationDeliveryAttempt.objects.filter(
            notification__organization=selected_org, ok=False, attempted_at__gte=since
        ).count()

        rule_errors = list(
            WorkflowRule.objects.filter(organization=selected_org, enabled=True, last_run_ok=False)
            .exclude(last_run_at__isnull=True)
            .order_by("-last_run_at")[:20]
        )

        policy, _ = AuditPolicy.objects.get_or_create(organization=selected_org)
        # Only allow policy changes when reauthed (same rule as /app/audit/).
        can_govern = _is_reauthed(request)

        org_status = {
            "pending_backups": int(pending_backups),
            "failed_backups_7d": list(failed_backups_7d),
            "recent_backups": recent_backups,
            "proxmox_connections": prox_conns,
            "unread_notifications": int(unread_notifications),
            "failed_deliveries_24h": int(failed_deliveries_24h),
            "workflow_rule_errors": rule_errors,
            "audit_policy": policy,
            "can_govern": bool(can_govern),
        }

    return render(
        request,
        "ui/super_admin_operations.html",
        {
            "org": org_ctx,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Operations", None)),
            "flash": flash,
            "is_reauthed": bool(is_reauthed),
            "reauth_url": reauth_url,
            "orgs": orgs,
            "selected_org": selected_org,
            "hb": hb,
            "org_status": org_status,
        },
    )


@login_required
def super_admin_org_detail(request: HttpRequest, org_id: int) -> HttpResponse:
    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    org_obj = get_object_or_404(Organization, id=org_id)
    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str, secret: str | None = None, secret_label: str | None = None):
        request.session["homeglue_flash"] = {"title": title, "body": body, "secret": secret, "secret_label": secret_label}

    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip()
        if action == "org_update":
            name = (request.POST.get("org_name") or "").strip()
            desc = (request.POST.get("org_description") or "").strip()
            if not name:
                _set_flash(title="Not saved", body="Name is required.")
                return redirect("ui:super_admin_org_detail", org_id=org_obj.id)
            # Enforce global uniqueness.
            if Organization.objects.exclude(id=org_obj.id).filter(name=name).exists():
                _set_flash(title="Not saved", body="That organization name already exists.")
                return redirect("ui:super_admin_org_detail", org_id=org_obj.id)
            org_obj.name = name
            org_obj.description = desc
            org_obj.save(update_fields=["name", "description"])
            _set_flash(title="Saved", body="Organization updated.")
            return redirect("ui:super_admin_org_detail", org_id=org_obj.id)

        if action == "member_add":
            username = (request.POST.get("username") or "").strip()
            role = (request.POST.get("role") or "member").strip()
            User = get_user_model()
            u = User.objects.filter(username=username).first()
            if not u:
                _set_flash(title="Member not added", body="User not found.")
                return redirect("ui:super_admin_org_detail", org_id=org_obj.id)
            role = role if role in {OrganizationMembership.ROLE_MEMBER, OrganizationMembership.ROLE_ADMIN, OrganizationMembership.ROLE_OWNER} else OrganizationMembership.ROLE_MEMBER
            OrganizationMembership.objects.update_or_create(organization=org_obj, user=u, defaults={"role": role})
            _set_flash(title="Member added", body=f"Added '{u.username}' to '{org_obj.name}'.")
            return redirect("ui:super_admin_org_detail", org_id=org_obj.id)

        if action == "member_set_role":
            mid = (request.POST.get("membership_id") or "").strip()
            role = (request.POST.get("role") or "member").strip()
            role = role if role in {OrganizationMembership.ROLE_MEMBER, OrganizationMembership.ROLE_ADMIN, OrganizationMembership.ROLE_OWNER} else OrganizationMembership.ROLE_MEMBER
            if mid.isdigit():
                m = OrganizationMembership.objects.filter(id=int(mid), organization=org_obj).first()
                if m:
                    m.role = role
                    m.save(update_fields=["role"])
                    _set_flash(title="Role updated", body=f"{m.user.username} is now {role}.")
            return redirect("ui:super_admin_org_detail", org_id=org_obj.id)

        if action == "member_remove":
            mid = (request.POST.get("membership_id") or "").strip()
            if mid.isdigit():
                OrganizationMembership.objects.filter(id=int(mid), organization=org_obj).delete()
                _set_flash(title="Member removed", body="Membership removed.")
            return redirect("ui:super_admin_org_detail", org_id=org_obj.id)

        if action == "user_create_and_add":
            username = (request.POST.get("username") or "").strip()
            email = (request.POST.get("email") or "").strip()
            pw = (request.POST.get("password") or "").strip()
            role = (request.POST.get("role") or "member").strip()
            role = role if role in {OrganizationMembership.ROLE_MEMBER, OrganizationMembership.ROLE_ADMIN, OrganizationMembership.ROLE_OWNER} else OrganizationMembership.ROLE_MEMBER
            if not username:
                _set_flash(title="User not created", body="Username is required.")
                return redirect("ui:super_admin_org_detail", org_id=org_obj.id)
            User = get_user_model()
            if User.objects.filter(username=username).exists():
                _set_flash(title="User not created", body="That username already exists.")
                return redirect("ui:super_admin_org_detail", org_id=org_obj.id)
            if not pw:
                import secrets

                pw = secrets.token_urlsafe(12)
            u = User.objects.create_user(username=username, email=email or "", password=pw)
            OrganizationMembership.objects.create(organization=org_obj, user=u, role=role)
            _set_flash(title="User created", body=f"Created '{u.username}' and added to '{org_obj.name}'.", secret=pw, secret_label="Temp password")
            return redirect("ui:super_admin_org_detail", org_id=org_obj.id)

    memberships = list(OrganizationMembership.objects.filter(organization=org_obj).select_related("user").order_by("role", "user__username")[:5000])

    return render(
        request,
        "ui/super_admin_org_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), (org_obj.name, None)),
            "org_obj": org_obj,
            "memberships": memberships,
            "flash": flash,
        },
    )


@login_required
def super_admin_system_settings(request: HttpRequest) -> HttpResponse:
    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    saved = False
    error = ""
    try:
        from apps.core.models import SystemSettings

        obj = SystemSettings.objects.first()
        if obj is None:
            obj = SystemSettings.objects.create()
    except Exception:
        obj = None
        error = "System settings table is not ready yet (run migrations)."

    if request.method == "POST" and request.POST.get("_action") == "save" and obj is not None:
        base_url = (request.POST.get("base_url") or "").strip().rstrip("/")
        ip_allowlist = (request.POST.get("ip_allowlist") or "").strip()
        ip_blocklist = (request.POST.get("ip_blocklist") or "").strip()
        trust = (request.POST.get("trust_x_forwarded_for") or "").strip() == "1"
        proxies = (request.POST.get("trusted_proxy_cidrs") or "").strip()
        cors_allowed_origins = (request.POST.get("cors_allowed_origins") or "").strip()
        csrf_trusted_origins = (request.POST.get("csrf_trusted_origins") or "").strip()
        allowed_hosts = (request.POST.get("allowed_hosts") or "").strip()
        reauth_ttl = (request.POST.get("reauth_ttl_seconds") or "").strip()
        webhook_timeout = (request.POST.get("webhook_timeout_seconds") or "").strip()
        smtp_timeout = (request.POST.get("smtp_timeout_seconds") or "").strip()
        obj.base_url = base_url
        obj.ip_allowlist = ip_allowlist
        obj.ip_blocklist = ip_blocklist
        obj.trust_x_forwarded_for = trust
        obj.trusted_proxy_cidrs = proxies
        obj.cors_allowed_origins = cors_allowed_origins
        obj.csrf_trusted_origins = csrf_trusted_origins
        obj.allowed_hosts = allowed_hosts
        try:
            obj.reauth_ttl_seconds = int(reauth_ttl or 900)
        except Exception:
            obj.reauth_ttl_seconds = 900
        try:
            obj.webhook_timeout_seconds = int(webhook_timeout or 8)
        except Exception:
            obj.webhook_timeout_seconds = 8
        try:
            obj.smtp_timeout_seconds = int(smtp_timeout or 10)
        except Exception:
            obj.smtp_timeout_seconds = 10
        obj.save()
        saved = True
        _audit_event(
            request=request,
            org=None,
            action=AuditEvent.ACTION_UPDATE,
            model="system.SystemSettings",
            object_pk=str(obj.id),
            summary="Updated system settings (base url / ip access control / cors / csrf / hosts / timeouts).",
        )

    return render(
        request,
        "ui/super_admin_system_settings.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("System settings", None)),
            "obj": obj
            or type(
                "Tmp",
                (),
                {
                    "base_url": "",
                    "ip_allowlist": "",
                    "ip_blocklist": "",
                    "trust_x_forwarded_for": False,
                    "trusted_proxy_cidrs": "",
                    "cors_allowed_origins": "",
                    "csrf_trusted_origins": "",
                    "allowed_hosts": "",
                    "reauth_ttl_seconds": 900,
                    "webhook_timeout_seconds": 8,
                    "smtp_timeout_seconds": 10,
                },
            )(),
            "saved": saved,
            "error": error,
        },
    )


@login_required
def super_admin_users_list(request: HttpRequest) -> HttpResponse:
    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    q = (request.GET.get("q") or "").strip().lower()
    User = get_user_model()
    qs = User.objects.all().order_by("username")
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(email__icontains=q))
    users = list(qs[:500])
    return render(
        request,
        "ui/super_admin_users_list.html",
        {"org": org, "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Users", None)), "q": q, "users": users},
    )


@login_required
def super_admin_user_detail(request: HttpRequest, user_id: int) -> HttpResponse:
    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser required.")

    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None

    flash = request.session.pop("homeglue_flash", None)

    def _set_flash(*, title: str, body: str, secret: str | None = None, secret_label: str | None = None):
        request.session["homeglue_flash"] = {"title": title, "body": body, "secret": secret, "secret_label": secret_label}

    User = get_user_model()
    target = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip()
        if action == "reset_password":
            import secrets

            pw = secrets.token_urlsafe(12)
            target.set_password(pw)
            target.save(update_fields=["password"])
            _set_flash(title="Password reset", body="New temporary password generated.", secret=pw, secret_label="Temp password")
            _audit_event(
                request=request,
                org=None,
                action=AuditEvent.ACTION_UPDATE,
                model="auth.User",
                object_pk=str(target.id),
                summary=f"Reset password for user '{target.username}'.",
            )
            return redirect("ui:super_admin_user_detail", user_id=target.id)

        if action == "save_profile":
            email = (request.POST.get("email") or "").strip()
            is_active = (request.POST.get("is_active") or "").strip() == "1"
            is_superuser = (request.POST.get("is_superuser") or "").strip() == "1"
            target.email = email
            target.is_active = is_active
            target.is_superuser = is_superuser
            target.is_staff = is_superuser or bool(getattr(target, "is_staff", False))
            target.save(update_fields=["email", "is_active", "is_superuser", "is_staff"])
            _set_flash(title="Saved", body="User updated.")
            _audit_event(
                request=request,
                org=None,
                action=AuditEvent.ACTION_UPDATE,
                model="auth.User",
                object_pk=str(target.id),
                summary=f"Updated user '{target.username}' (email/active/superuser).",
            )
            return redirect("ui:super_admin_user_detail", user_id=target.id)

    memberships = list(
        OrganizationMembership.objects.filter(user=target).select_related("organization").order_by("organization__name")[:5000]
    )
    return render(
        request,
        "ui/super_admin_user_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Admin", reverse("ui:super_admin_home")), ("Users", reverse("ui:super_admin_users_list")), (target.username, None)),
            "target": target,
            "memberships": memberships,
            "flash": flash,
        },
    )


@login_required
def version_compare(request: HttpRequest, version_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization

    v_new = get_object_or_404(ObjectVersion.objects.select_related("content_type", "created_by"), organization=org, id=version_id)
    try:
        to_id = int((request.GET.get("to") or "").strip() or "0")
    except Exception:
        to_id = 0

    v_old = None
    if to_id:
        v_old = get_object_or_404(
            ObjectVersion.objects.select_related("content_type", "created_by"),
            organization=org,
            id=to_id,
            content_type=v_new.content_type,
            object_id=v_new.object_id,
        )
    else:
        v_old = (
            ObjectVersion.objects.filter(
                organization=org,
                content_type=v_new.content_type,
                object_id=v_new.object_id,
                created_at__lt=v_new.created_at,
            )
            .select_related("content_type", "created_by")
            .order_by("-created_at")
            .first()
        )

    if not v_old:
        raise PermissionDenied("No earlier version available to compare.")

    model_cls = v_new.content_type.model_class()
    if model_cls is None:
        raise PermissionDenied("Invalid version model.")

    if model_cls not in (Document, DocumentTemplate):
        raise PermissionDenied("Compare is only supported for Documents and Templates right now.")

    # Best-effort permission check aligned with object detail visibility.
    if model_cls is Document:
        can_admin = _is_org_admin(request.user, org)
        dqs = Document.objects.filter(organization=org)
        if not (can_admin or getattr(request.user, "is_superuser", False)):
            dqs = dqs.filter(_visible_docs_q(request.user, org)).distinct()
        if not dqs.filter(id=int(v_new.object_id)).exists():
            raise PermissionDenied("Not allowed.")

    # Diff is based on stored snapshots, with a conservative allowlist per model.
    snap_new = _safe_snapshot_fields(v_new.snapshot or {})
    snap_old = _safe_snapshot_fields(v_old.snapshot or {})
    model_key = (snap_new.get("model") or "").strip()

    # Attach ids for diff labels.
    snap_new["id"] = v_new.id
    snap_old["id"] = v_old.id

    diff = _version_diff_rows(org=org, model_key=model_key, newer=snap_new, older=snap_old)
    hidden = sorted(set((snap_new.get("hidden") or []) + (snap_old.get("hidden") or [])))

    obj_label = _human_model_label(f"{v_new.content_type.app_label}.{v_new.content_type.model}")
    back_url = _ui_object_url(v_new.content_type.app_label, v_new.content_type.model, v_new.object_id) or reverse("ui:dashboard")

    return render(
        request,
        "ui/version_compare.html",
        {
            "org": org,
            "crumbs": _crumbs(("Versions", None), (f"Compare", None)),
            "obj_label": obj_label,
            "object_id": v_new.object_id,
            "back_url": back_url,
            "v_new": v_new,
            "v_old": v_old,
            "diff": diff,
            "hidden_fields": hidden,
        },
    )


@login_required
def leave_org(request: HttpRequest) -> HttpResponse:
    ctx = get_current_org_context(request)
    org = ctx.organization if ctx else None
    if org is not None:
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_UPDATE,
            model="security.OrgSession",
            object_pk=str(getattr(request.user, "id", "")),
            summary=f"Left organization '{org.name}'.",
        )
    clear_current_org(request)
    return redirect("ui:home")


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    recent_events = list(AuditEvent.objects.filter(organization=org).select_related("user").order_by("-ts")[:20])
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)

    docs_qs = Document.objects.filter(organization=org, archived_at__isnull=True)
    if not can_admin:
        docs_qs = docs_qs.filter(_visible_docs_q(request.user, org)).distinct()

    pw_qs = PasswordEntry.objects.filter(organization=org, archived_at__isnull=True)
    if not can_admin:
        pw_qs = pw_qs.filter(_visible_passwords_q(request.user, org)).distinct()

    return render(
        request,
        "ui/dashboard.html",
        {
            "org": org,
            "crumbs": _crumbs(("Dashboard", None)),
            "completion": _completion_profile(org=org, user=request.user, details=False),
            "counts": {
                "assets": Asset.objects.filter(organization=org, archived_at__isnull=True).count(),
                "documents": docs_qs.count(),
                "passwords": pw_qs.count(),
                "checklists": Checklist.objects.filter(organization=org, archived_at__isnull=True).count(),
                "domains": Domain.objects.filter(organization=org, archived_at__isnull=True).count(),
                "sslcerts": SSLCertificate.objects.filter(organization=org, archived_at__isnull=True).count(),
                "flex_assets": FlexibleAsset.objects.filter(organization=org, archived_at__isnull=True).count(),
                "relationships": Relationship.objects.filter(organization=org).count(),
            },
            "recent": [_audit_event_view_row(e) for e in recent_events],
        },
    )


@login_required
def reports(request: HttpRequest) -> HttpResponse:
    """
    Small "what's missing" report hub (MVP).
    """
    ctx = require_current_org(request)
    org = ctx.organization
    from datetime import date, timedelta

    def _can_admin() -> bool:
        return _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)

    def _visible_passwords_qs():
        qs = PasswordEntry.objects.filter(organization=org, archived_at__isnull=True)
        if not _can_admin():
            qs = qs.filter(_visible_passwords_q(request.user, org)).distinct()
        return qs

    today = date.today()
    soon30 = today + timedelta(days=30)
    soon90 = today + timedelta(days=90)
    soon7 = today + timedelta(days=7)

    domains_30 = list(
        Domain.objects.filter(organization=org, archived_at__isnull=True, expires_on__isnull=False, expires_on__lte=soon30)
        .order_by("expires_on")[:50]
    )
    domains_90 = list(
        Domain.objects.filter(organization=org, archived_at__isnull=True, expires_on__isnull=False, expires_on__lte=soon90)
        .order_by("expires_on")[:50]
    )
    certs_30 = list(
        SSLCertificate.objects.filter(organization=org, archived_at__isnull=True, not_after__isnull=False, not_after__lte=soon30)
        .order_by("not_after")[:50]
    )
    certs_90 = list(
        SSLCertificate.objects.filter(organization=org, archived_at__isnull=True, not_after__isnull=False, not_after__lte=soon90)
        .order_by("not_after")[:50]
    )

    assets_no_location = list(Asset.objects.filter(organization=org, archived_at__isnull=True, location__isnull=True).order_by("name")[:50])
    passwords_no_url = list(_visible_passwords_qs().filter(Q(url="") | Q(url__isnull=True)).order_by("name")[:50])
    # Rotation due in 30 days (best-effort; computed in Python for now).
    pw_rotation_due = []
    try:
        for p in _visible_passwords_qs().filter(rotation_interval_days__gt=0).order_by("name")[:2000]:
            due = p.rotation_due_on()
            if due and due <= soon30:
                pw_rotation_due.append({"entry": p, "due_on": due, "overdue": due < today})
        pw_rotation_due.sort(key=lambda x: (x["due_on"], x["entry"].name))
        pw_rotation_due = pw_rotation_due[:50]
    except Exception:
        pw_rotation_due = []
    runs_overdue = list(
        ChecklistRun.objects.filter(organization=org, archived_at__isnull=True, status=ChecklistRun.STATUS_OPEN, due_on__isnull=False, due_on__lt=today)
        .order_by("due_on")[:50]
    )
    runs_due7 = list(
        ChecklistRun.objects.filter(organization=org, archived_at__isnull=True, status=ChecklistRun.STATUS_OPEN, due_on__isnull=False, due_on__lte=soon7)
        .order_by("due_on")[:50]
    )

    completion = _completion_profile(org=org, user=request.user)

    return render(
        request,
        "ui/reports.html",
        {
            "org": org,
            "crumbs": _crumbs(("Reports", None)),
            "today": today,
            "completion": completion,
            "domains_30": domains_30,
            "domains_90": domains_90,
            "certs_30": certs_30,
            "certs_90": certs_90,
            "assets_no_location": assets_no_location,
            "passwords_no_url": passwords_no_url,
            "pw_rotation_due": pw_rotation_due,
            "runs_overdue": runs_overdue,
            "runs_due7": runs_due7,
        },
    )


@login_required
def audit_log(request: HttpRequest) -> HttpResponse:
    """
    Central audit explorer for org admins.
    """

    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    policy, _ = AuditPolicy.objects.get_or_create(organization=org)
    reauth_url = reverse("ui:reauth") + "?" + urlencode({"next": request.get_full_path()})

    if request.method == "POST":
        action_post = (request.POST.get("_action") or "").strip()
        if action_post in {"policy_save", "purge_now"} and not _is_reauthed(request):
            return redirect(reauth_url)
        if action_post == "policy_save":
            enabled = (request.POST.get("enabled") or "").strip() == "1"
            try:
                retention_days = int(request.POST.get("retention_days") or 365)
            except Exception:
                retention_days = 365
            retention_days = max(7, min(3650, retention_days))
            policy.enabled = enabled
            policy.retention_days = retention_days
            policy.save(update_fields=["enabled", "retention_days", "updated_at"])
            AuditEvent.objects.create(
                organization=org,
                user=request.user if request.user.is_authenticated else None,
                action=AuditEvent.ACTION_UPDATE,
                model="audit.AuditPolicy",
                object_pk=str(policy.id),
                summary=f"Updated audit policy: enabled={int(enabled)}, retention_days={retention_days}.",
            )
            return redirect("ui:audit_log")
        if action_post == "purge_now":
            purged = 0
            if policy.enabled:
                cutoff = timezone.now() - timedelta(days=int(policy.retention_days or 365))
                purged, _ = AuditEvent.objects.filter(organization=org, ts__lt=cutoff).delete()
            AuditEvent.objects.create(
                organization=org,
                user=request.user if request.user.is_authenticated else None,
                action=AuditEvent.ACTION_UPDATE,
                model="audit.AuditPolicy",
                object_pk=str(policy.id),
                summary=f"Audit purge executed; removed {int(purged)} event(s).",
            )
            return redirect("ui:audit_log")

    q = (request.GET.get("q") or "").strip()
    action = (request.GET.get("action") or "").strip().lower()
    model = (request.GET.get("model") or "").strip()
    user_filter = (request.GET.get("user") or "").strip().lower()
    date_from_raw = (request.GET.get("date_from") or "").strip()
    date_to_raw = (request.GET.get("date_to") or "").strip()
    out_format = (request.GET.get("format") or "").strip().lower()
    limit_raw = (request.GET.get("limit") or "").strip()

    try:
        limit = int(limit_raw or 500)
    except Exception:
        limit = 500
    limit = max(1, min(5000, limit))

    qs = AuditEvent.objects.filter(organization=org).select_related("user").order_by("-ts")

    if action in {AuditEvent.ACTION_CREATE, AuditEvent.ACTION_UPDATE, AuditEvent.ACTION_DELETE}:
        qs = qs.filter(action=action)
    if model:
        qs = qs.filter(model__icontains=model)
    if user_filter == "system":
        qs = qs.filter(user__isnull=True)
    elif user_filter == "human":
        qs = qs.filter(user__isnull=False)
    elif user_filter.isdigit():
        qs = qs.filter(user_id=int(user_filter))
    if q:
        qs = qs.filter(
            Q(summary__icontains=q)
            | Q(model__icontains=q)
            | Q(object_pk__icontains=q)
            | Q(user__username__icontains=q)
            | Q(ip__icontains=q)
        )

    try:
        if date_from_raw:
            dt = datetime.strptime(date_from_raw, "%Y-%m-%d")
            qs = qs.filter(ts__date__gte=dt.date())
    except Exception:
        date_from_raw = ""
    try:
        if date_to_raw:
            dt = datetime.strptime(date_to_raw, "%Y-%m-%d")
            qs = qs.filter(ts__date__lte=dt.date())
    except Exception:
        date_to_raw = ""

    if out_format == "csv":
        rows = list(qs[:limit])
        resp = HttpResponse(content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="audit-log-{org.id}.csv"'
        w = csv.writer(resp)
        w.writerow(["timestamp", "action", "model", "object_pk", "user", "ip", "summary"])
        for e in rows:
            w.writerow(
                [
                    e.ts.isoformat() if e.ts else "",
                    e.action or "",
                    e.model or "",
                    e.object_pk or "",
                    (e.user.username if e.user else "system"),
                    e.ip or "",
                    e.summary or "",
                ]
            )
        return resp

    now = timezone.now()
    day_ago = now - timedelta(days=1)
    stats_24h_qs = AuditEvent.objects.filter(organization=org, ts__gte=day_ago)
    stats_24h = {
        "total": stats_24h_qs.count(),
        "create": stats_24h_qs.filter(action=AuditEvent.ACTION_CREATE).count(),
        "update": stats_24h_qs.filter(action=AuditEvent.ACTION_UPDATE).count(),
        "delete": stats_24h_qs.filter(action=AuditEvent.ACTION_DELETE).count(),
        "system": stats_24h_qs.filter(user__isnull=True).count(),
    }
    top_models = list(
        stats_24h_qs.values("model").annotate(c=Count("id")).order_by("-c", "model")[:8]
    )

    items = list(qs[:limit])
    items_view = [_audit_event_view_row(e) for e in items]
    model_choices_raw = list(
        AuditEvent.objects.filter(organization=org).values_list("model", flat=True).distinct().order_by("model")[:200]
    )
    model_choices = [{"value": m, "label": _human_model_label(m)} for m in model_choices_raw]
    return render(
        request,
        "ui/audit_log.html",
        {
            "org": org,
            "crumbs": _crumbs(("Audit Log", None)),
            "items": items_view,
            "q": q,
            "action": action,
            "model": model,
            "user_filter": user_filter,
            "date_from": date_from_raw,
            "date_to": date_to_raw,
            "limit": limit,
            "model_choices": model_choices,
            "policy": policy,
            "is_reauthed": _is_reauthed(request),
            "reauth_url": reauth_url,
            "stats_24h": stats_24h,
            "top_models": top_models,
            "export_url": reverse("ui:audit_log") + "?" + urlencode(
                {
                    "q": q,
                    "action": action,
                    "model": model,
                    "user": user_filter,
                    "date_from": date_from_raw,
                    "date_to": date_to_raw,
                    "limit": str(limit),
                    "format": "csv",
                }
            ),
        },
    )


@login_required
def search(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    results = []
    ids_by_type: dict[str, list[int]] = {}
    archived_mode = _archived_mode(request)

    # Build archived toggle URLs (Active / Archived / All) while preserving other query params.
    params = request.GET.copy()
    params.pop("archived", None)
    base = request.path
    active_url = base + (("?" + params.urlencode()) if params else "")
    params_arch = request.GET.copy()
    params_arch["archived"] = "1"
    archived_url = base + "?" + params_arch.urlencode()
    params_all = request.GET.copy()
    params_all["archived"] = "include"
    all_url = base + "?" + params_all.urlencode()

    TYPE_LABELS: dict[str, str] = {
        "asset": "Assets",
        "config": "Config Items",
        "doc": "Docs",
        "template": "Templates",
        "note": "Notes",
        "file": "Files",
        "password": "Passwords",
        "contact": "Contacts",
        "location": "Locations",
        "domain": "Domains",
        "sslcert": "SSL Certs",
        "checklist": "Checklists",
        "flex": "Flexible Assets",
        "tag": "Tags",
    }
    raw_types = [str(x or "").strip() for x in request.GET.getlist("t") if str(x or "").strip()]
    # Allow a single comma-separated param too.
    if len(raw_types) == 1 and "," in raw_types[0]:
        raw_types = [p.strip() for p in raw_types[0].split(",") if p.strip()]
    selected_types = {t.lower() for t in raw_types if t}
    selected_types = {t for t in selected_types if t in TYPE_LABELS}

    def _want(t: str) -> bool:
        # No filter means "all types".
        return (not selected_types) or (t in selected_types)

    if q:
        if _want("asset"):
            aqs = _filter_archived_qs(request, Asset.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = (
                        SearchVector("name", weight="A")
                        + SearchVector("manufacturer", weight="B")
                        + SearchVector("model", weight="B")
                        + SearchVector("serial_number", weight="B")
                        + SearchVector("notes", weight="C")
                    )
                    aqs2 = _fts_ranked(aqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "name")
                except Exception:
                    aqs2 = aqs.filter(Q(name__icontains=q) | Q(serial_number__icontains=q) | Q(manufacturer__icontains=q) | Q(model__icontains=q)).order_by("name")
            else:
                aqs2 = aqs.filter(Q(name__icontains=q) | Q(serial_number__icontains=q) | Q(manufacturer__icontains=q) | Q(model__icontains=q)).order_by("name")
            for obj in aqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(
                    " ".join([x for x in [obj.manufacturer, obj.model, obj.serial_number, obj.notes] if x]),
                    q,
                )
                results.append(
                    {
                        "type": "asset",
                        "label": obj.name,
                        "url": reverse("ui:asset_detail", kwargs={"asset_id": obj.id}),
                        "meta": obj.get_asset_type_display(),
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": 0.0,
                    }
                )
                results[-1]["score"] = score
                ids_by_type.setdefault("asset", []).append(int(obj.id))

        if _want("config"):
            cqs = _filter_archived_qs(request, ConfigurationItem.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("name", weight="A") + SearchVector("hostname", weight="B") + SearchVector("notes", weight="C")
                    cqs2 = _fts_ranked(cqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "name")
                except Exception:
                    cqs2 = cqs.filter(Q(name__icontains=q) | Q(hostname__icontains=q) | Q(primary_ip__icontains=q)).order_by("name")
            else:
                cqs2 = cqs.filter(Q(name__icontains=q) | Q(hostname__icontains=q) | Q(primary_ip__icontains=q)).order_by("name")
            for obj in cqs2[:25]:
                meta = obj.hostname or (str(obj.primary_ip) if obj.primary_ip else obj.get_ci_type_display())
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(" ".join([x for x in [obj.hostname, str(obj.primary_ip or ""), obj.notes] if x]), q)
                results.append(
                    {
                        "type": "config",
                        "label": obj.name,
                        "url": reverse("ui:config_item_detail", kwargs={"item_id": obj.id}),
                        "meta": meta,
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("config", []).append(int(obj.id))

        if _want("contact"):
            coqs = _filter_archived_qs(request, Contact.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("first_name", weight="A") + SearchVector("last_name", weight="A") + SearchVector("email", weight="B") + SearchVector("notes", weight="C")
                    coqs2 = _fts_ranked(coqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "last_name", "first_name")
                except Exception:
                    coqs2 = coqs.filter(Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q)).order_by("last_name", "first_name")
            else:
                coqs2 = coqs.filter(Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q)).order_by("last_name", "first_name")
            for obj in coqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(" ".join([x for x in [obj.email, obj.phone, obj.notes] if x]), q)
                results.append(
                    {
                        "type": "contact",
                        "label": str(obj),
                        "url": reverse("ui:contact_detail", kwargs={"contact_id": obj.id}),
                        "meta": obj.email or "",
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("contact", []).append(int(obj.id))

        if _want("doc"):
            dqs = _filter_archived_qs(request, Document.objects.filter(organization=org))
            if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
                dqs = dqs.filter(_visible_docs_q(request.user, org)).distinct()
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector, SearchQuery, SearchRank, SearchHeadline

                    vector = SearchVector("title", weight="A") + SearchVector("body", weight="B")
                    query = SearchQuery(q, search_type="websearch")
                    dqs2 = dqs.annotate(
                        _fts_rank=SearchRank(vector, query),
                        _hl=SearchHeadline("body", query, start_sel="[[[", stop_sel="]]]", max_words=32, min_words=12, highlight_all=True),
                    ).filter(_fts_rank__gt=0.0)
                    dqs2 = dqs2.order_by("-_fts_rank", "-updated_at")
                except Exception:
                    dqs2 = dqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-updated_at")
            else:
                dqs2 = dqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-updated_at")
            for obj in dqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                hl = getattr(obj, "_hl", "") or ""
                snippet_html = _snippet_html_from_headline(hl) if hl else _snippet_html_from_text(obj.body or "", q)
                results.append(
                    {
                        "type": "doc",
                        "label": obj.title,
                        "url": reverse("ui:document_detail", kwargs={"document_id": obj.id}),
                        "meta": obj.updated_at.strftime("%Y-%m-%d"),
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("doc", []).append(int(obj.id))

        if _want("note"):
            nqs = _notes_qs_for_user(user=request.user, org=org)
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector, SearchQuery, SearchRank, SearchHeadline

                    vector = SearchVector("title", weight="A") + SearchVector("body", weight="B")
                    query = SearchQuery(q, search_type="websearch")
                    nqs2 = nqs.annotate(
                        _fts_rank=SearchRank(vector, query),
                        _hl=SearchHeadline("body", query, start_sel="[[[", stop_sel="]]]", max_words=28, min_words=10, highlight_all=True),
                    ).filter(_fts_rank__gt=0.0)
                    nqs2 = nqs2.order_by("-_fts_rank", "-created_at")
                except Exception:
                    nqs2 = nqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-created_at")
            else:
                nqs2 = nqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-created_at")
            for obj in nqs2[:25]:
                label = obj.title or f"Note {obj.id}"
                meta = obj.created_at.strftime("%Y-%m-%d")
                if obj.content_type_id and obj.object_id:
                    meta = f"{meta} · {_human_ref_label(ct=obj.content_type, oid=obj.object_id)}"
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                hl = getattr(obj, "_hl", "") or ""
                snippet_html = _snippet_html_from_headline(hl) if hl else _snippet_html_from_text(obj.body or "", q)
                results.append(
                    {
                        "type": "note",
                        "label": label,
                        "url": reverse("ui:note_detail", kwargs={"note_id": obj.id}),
                        "meta": meta,
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("note", []).append(int(obj.id))

        if _want("file"):
            fqs = _attachments_qs_for_user(user=request.user, org=org)
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("filename", weight="A")
                    fqs2 = _fts_ranked(fqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "-created_at")
                    if not fqs2.exists():
                        fqs2 = fqs.filter(filename__icontains=q).order_by("-created_at")
                except Exception:
                    fqs2 = fqs.filter(filename__icontains=q).order_by("-created_at")
            else:
                fqs2 = fqs.filter(filename__icontains=q).order_by("-created_at")
            for obj in fqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                meta = obj.created_at.strftime("%Y-%m-%d")
                if obj.folder_id and obj.folder:
                    meta = f"{meta} · {obj.folder.name}"
                if obj.content_type_id and obj.object_id:
                    meta = f"{meta} · {_human_ref_label(ct=obj.content_type, oid=obj.object_id)}"
                snippet_html = _snippet_html_from_text(meta, q) if q else ""
                results.append(
                    {
                        "type": "file",
                        "label": obj.filename or f"File {obj.id}",
                        "url": reverse("ui:file_detail", kwargs={"attachment_id": obj.id}),
                        "meta": meta,
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("file", []).append(int(obj.id))

        if _want("password"):
            pqs = _filter_archived_qs(request, PasswordEntry.objects.filter(organization=org))
            if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
                pqs = pqs.filter(_visible_passwords_q(request.user, org)).distinct()
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("name", weight="A") + SearchVector("username", weight="B") + SearchVector("url", weight="B") + SearchVector("notes", weight="C")
                    pqs2 = _fts_ranked(pqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "name")
                except Exception:
                    pqs2 = pqs.filter(Q(name__icontains=q) | Q(username__icontains=q) | Q(url__icontains=q) | Q(notes__icontains=q)).order_by("name")
            else:
                pqs2 = pqs.filter(Q(name__icontains=q) | Q(username__icontains=q) | Q(url__icontains=q) | Q(notes__icontains=q)).order_by("name")
            for obj in pqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(" ".join([x for x in [obj.username, obj.url, obj.notes] if x]), q)
                results.append(
                    {
                        "type": "password",
                        "label": obj.name,
                        "url": reverse("ui:password_detail", kwargs={"password_id": obj.id}),
                        "meta": obj.username or "",
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("password", []).append(int(obj.id))

        if _want("location"):
            lqs = _filter_archived_qs(request, Location.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("name", weight="A") + SearchVector("address", weight="B")
                    lqs2 = _fts_ranked(lqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "name")
                except Exception:
                    lqs2 = lqs.filter(Q(name__icontains=q) | Q(address__icontains=q)).order_by("name")
            else:
                lqs2 = lqs.filter(Q(name__icontains=q) | Q(address__icontains=q)).order_by("name")
            for obj in lqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(obj.address or "", q)
                results.append(
                    {
                        "type": "location",
                        "label": obj.name,
                        "url": reverse("ui:location_detail", kwargs={"location_id": obj.id}),
                        "meta": (obj.address or "")[:60],
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("location", []).append(int(obj.id))

        if _want("template"):
            tqs = _filter_archived_qs(request, DocumentTemplate.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector, SearchQuery, SearchRank, SearchHeadline

                    vector = SearchVector("name", weight="A") + SearchVector("body", weight="B")
                    query = SearchQuery(q, search_type="websearch")
                    tqs2 = tqs.annotate(
                        _fts_rank=SearchRank(vector, query),
                        _hl=SearchHeadline("body", query, start_sel="[[[", stop_sel="]]]", max_words=28, min_words=10, highlight_all=True),
                    ).filter(_fts_rank__gt=0.0)
                    tqs2 = tqs2.order_by("-_fts_rank", "name")
                except Exception:
                    tqs2 = tqs.filter(Q(name__icontains=q) | Q(body__icontains=q)).order_by("name")
            else:
                tqs2 = tqs.filter(Q(name__icontains=q) | Q(body__icontains=q)).order_by("name")
            for obj in tqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                hl = getattr(obj, "_hl", "") or ""
                snippet_html = _snippet_html_from_headline(hl) if hl else _snippet_html_from_text(obj.body or "", q)
                results.append(
                    {
                        "type": "template",
                        "label": obj.name,
                        "url": reverse("ui:template_detail", kwargs={"template_id": obj.id}),
                        "meta": "doc template",
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("template", []).append(int(obj.id))

        if _want("domain"):
            doqs = _filter_archived_qs(request, Domain.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("name", weight="A") + SearchVector("registrar", weight="B") + SearchVector("dns_provider", weight="B") + SearchVector("notes", weight="C")
                    doqs2 = _fts_ranked(doqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "name")
                    # FTS doesn't tokenize hostnames/domains how humans expect (dots often require exact match).
                    # Fall back to icontains when FTS yields no results.
                    if not doqs2.exists():
                        doqs2 = doqs.filter(Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q) | Q(notes__icontains=q)).order_by("name")
                except Exception:
                    doqs2 = doqs.filter(Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q) | Q(notes__icontains=q)).order_by("name")
            else:
                doqs2 = doqs.filter(Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q) | Q(notes__icontains=q)).order_by("name")
            for obj in doqs2[:25]:
                meta = obj.expires_on.isoformat() if obj.expires_on else ""
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(" ".join([x for x in [obj.registrar, obj.dns_provider, obj.notes] if x]), q)
                results.append(
                    {
                        "type": "domain",
                        "label": obj.name,
                        "url": reverse("ui:domain_detail", kwargs={"domain_id": obj.id}),
                        "meta": meta,
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("domain", []).append(int(obj.id))

        if _want("sslcert"):
            sqs = _filter_archived_qs(request, SSLCertificate.objects.filter(organization=org))
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("common_name", weight="A") + SearchVector("subject_alt_names", weight="B") + SearchVector("issuer", weight="B") + SearchVector("serial_number", weight="C") + SearchVector("fingerprint_sha256", weight="C") + SearchVector("notes", weight="D")
                    sqs2 = _fts_ranked(sqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "not_after", "common_name")
                    if not sqs2.exists():
                        sqs2 = sqs.filter(Q(common_name__icontains=q) | Q(subject_alt_names__icontains=q) | Q(issuer__icontains=q) | Q(notes__icontains=q)).order_by("not_after", "common_name")
                except Exception:
                    sqs2 = sqs.filter(Q(common_name__icontains=q) | Q(subject_alt_names__icontains=q) | Q(issuer__icontains=q) | Q(notes__icontains=q)).order_by("not_after", "common_name")
            else:
                sqs2 = sqs.filter(Q(common_name__icontains=q) | Q(subject_alt_names__icontains=q) | Q(issuer__icontains=q) | Q(notes__icontains=q)).order_by("not_after", "common_name")
            for obj in sqs2[:25]:
                meta = obj.not_after.isoformat() if obj.not_after else ""
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(" ".join([x for x in [obj.issuer, obj.subject_alt_names, obj.notes] if x]), q)
                results.append(
                    {
                        "type": "sslcert",
                        "label": obj.common_name or f"Cert {obj.id}",
                        "url": reverse("ui:sslcert_detail", kwargs={"sslcert_id": obj.id}),
                        "meta": meta,
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("sslcert", []).append(int(obj.id))

        if _want("checklist"):
            for obj in (
                _filter_archived_qs(request, Checklist.objects.filter(organization=org))
                .filter(Q(name__icontains=q) | Q(description__icontains=q))
                .order_by("-updated_at", "name")[:25]
            ):
                snippet_html = _snippet_html_from_text(obj.description or "", q)
                results.append(
                    {
                        "type": "checklist",
                        "label": obj.name,
                        "url": reverse("ui:checklist_detail", kwargs={"checklist_id": obj.id}),
                        "meta": obj.updated_at.strftime("%Y-%m-%d"),
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": 0.0,
                    }
                )
                ids_by_type.setdefault("checklist", []).append(int(obj.id))

        if _want("flex"):
            fqs = _filter_archived_qs(request, FlexibleAsset.objects.filter(organization=org)).select_related("asset_type")
            if _is_postgres():
                try:
                    from django.contrib.postgres.search import SearchVector

                    vector = SearchVector("name", weight="A") + SearchVector("notes", weight="B")
                    fqs2 = _fts_ranked(fqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "name")
                except Exception:
                    fqs2 = fqs.filter(Q(name__icontains=q) | Q(notes__icontains=q)).order_by("name")
            else:
                fqs2 = fqs.filter(Q(name__icontains=q) | Q(notes__icontains=q)).order_by("name")
            for obj in fqs2[:25]:
                score = float(getattr(obj, "_fts_rank", 0.0) or 0.0)
                snippet_html = _snippet_html_from_text(obj.notes or "", q)
                results.append(
                    {
                        "type": "flex",
                        "label": obj.name,
                        "url": reverse("ui:flex_asset_detail", kwargs={"type_id": obj.asset_type_id, "asset_id": obj.id}),
                        "meta": obj.asset_type.name,
                        "snippet_html": snippet_html,
                        "obj_id": obj.id,
                        "ref": _ref_for_obj(obj),
                        "score": score,
                    }
                )
                ids_by_type.setdefault("flex", []).append(int(obj.id))

        if _want("tag"):
            for obj in Tag.objects.filter(Q(organization__isnull=True) | Q(organization=org)).filter(name__icontains=q).order_by("name")[:25]:
                scope = "global" if obj.organization_id is None else "org"
                results.append({"type": "tag", "label": obj.name, "url": reverse("ui:tag_detail", kwargs={"tag_id": obj.id}), "meta": scope, "score": 0.0})

        rel_counts_by_type: dict[str, dict[int, int]] = {
            "asset": _relationship_counts_for_model(org=org, model_cls=Asset, ids=ids_by_type.get("asset", [])),
            "config": _relationship_counts_for_model(
                org=org, model_cls=ConfigurationItem, ids=ids_by_type.get("config", [])
            ),
            "contact": _relationship_counts_for_model(org=org, model_cls=Contact, ids=ids_by_type.get("contact", [])),
            "doc": _relationship_counts_for_model(org=org, model_cls=Document, ids=ids_by_type.get("doc", [])),
            "note": _relationship_counts_for_model(org=org, model_cls=Note, ids=ids_by_type.get("note", [])),
            "file": _relationship_counts_for_model(org=org, model_cls=Attachment, ids=ids_by_type.get("file", [])),
            "password": _relationship_counts_for_model(
                org=org, model_cls=PasswordEntry, ids=ids_by_type.get("password", [])
            ),
            "location": _relationship_counts_for_model(
                org=org, model_cls=Location, ids=ids_by_type.get("location", [])
            ),
            "template": _relationship_counts_for_model(
                org=org, model_cls=DocumentTemplate, ids=ids_by_type.get("template", [])
            ),
            "domain": _relationship_counts_for_model(
                org=org, model_cls=Domain, ids=ids_by_type.get("domain", [])
            ),
            "sslcert": _relationship_counts_for_model(
                org=org, model_cls=SSLCertificate, ids=ids_by_type.get("sslcert", [])
            ),
            "checklist": _relationship_counts_for_model(
                org=org, model_cls=Checklist, ids=ids_by_type.get("checklist", [])
            ),
        }
        for r in results:
            t = r.get("type")
            oid = r.get("obj_id")
            if t in rel_counts_by_type and oid is not None:
                r["rel_count"] = int(rel_counts_by_type[t].get(int(oid), 0))
            else:
                r["rel_count"] = 0

        # Prefer relevance when available; fall back to type/label for stable ordering.
        results.sort(key=lambda r: (-float(r.get("score") or 0.0), str(r.get("type") or ""), str(r.get("label") or "")))

    return render(
        request,
        "ui/search.html",
        {
            "org": org,
            "crumbs": _crumbs(("Search", None)),
            "q": q,
            "results": results,
            "archived_mode": archived_mode,
            "active_url": active_url,
            "archived_url": archived_url,
            "all_url": all_url,
            "type_filters": [
                {"key": k, "label": TYPE_LABELS[k], "checked": (k in selected_types) or (not selected_types)}
                for k in TYPE_LABELS.keys()
            ],
        },
    )


@login_required
def quick_palette(request: HttpRequest) -> JsonResponse:
    """
    Keyboard palette datasource.
    Returns a JSON list of items: {type,label,meta,url}
    """
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()

    items: list[dict] = []

    # Always-present actions.
    items.extend(
        [
            {"section": "Actions", "type": "action", "label": "Search", "meta": "Jump to search page", "url": reverse("ui:search")},
            {"section": "Actions", "type": "action", "label": "Reports", "meta": "What's missing / expiring soon", "url": reverse("ui:reports")},
            {"section": "Actions", "type": "action", "label": "Flexible Assets", "meta": "Types and assets", "url": reverse("ui:flex_types_list")},
            {"section": "Actions", "type": "action", "label": "Integrations", "meta": "Connect external systems", "url": reverse("ui:integrations_list")},
            {"section": "Actions", "type": "action", "label": "New asset", "meta": "Create an asset", "url": reverse("ui:assets_new")},
            {"section": "Actions", "type": "action", "label": "New config item", "meta": "Create a config item", "url": reverse("ui:config_items_new")},
            {"section": "Actions", "type": "action", "label": "New doc", "meta": "Create a doc", "url": reverse("ui:documents_new")},
            {"section": "Actions", "type": "action", "label": "New password", "meta": "Create a password entry", "url": reverse("ui:passwords_new")},
            {"section": "Actions", "type": "action", "label": "New checklist", "meta": "Create a checklist", "url": reverse("ui:checklists_new")},
            {"section": "Actions", "type": "action", "label": "New checklist run", "meta": "Create a run (execution instance)", "url": reverse("ui:checklist_runs_new")},
            {"section": "Actions", "type": "action", "label": "New domain", "meta": "Create a domain record", "url": reverse("ui:domains_new")},
            {"section": "Actions", "type": "action", "label": "New SSL certificate", "meta": "Create a certificate record", "url": reverse("ui:sslcerts_new")},
            {"section": "Actions", "type": "action", "label": "Switch org", "meta": "Leave current org", "url": reverse("ui:leave_org")},
        ]
    )

    if q:
        # "Create named" shortcuts.
        q_enc = urlencode({"name": q})
        items.extend(
            [
                {"section": "Create", "type": "action", "label": f"New asset: {q}", "meta": "Prefill name", "url": reverse("ui:assets_new") + f"?{q_enc}"},
                {"section": "Create", "type": "action", "label": f"New config item: {q}", "meta": "Prefill name", "url": reverse("ui:config_items_new") + f"?{q_enc}"},
                {"section": "Create", "type": "action", "label": f"New template: {q}", "meta": "Prefill name", "url": reverse("ui:templates_new") + f"?{q_enc}"},
                {"section": "Create", "type": "action", "label": f"New password: {q}", "meta": "Prefill name", "url": reverse("ui:passwords_new") + f"?{q_enc}"},
                {"section": "Create", "type": "action", "label": f"New checklist: {q}", "meta": "Prefill name", "url": reverse("ui:checklists_new") + f"?{q_enc}"},
                {"section": "Create", "type": "action", "label": f"New domain: {q}", "meta": "Prefill name", "url": reverse("ui:domains_new") + f"?{q_enc}"},
            ]
        )
        cn_enc = urlencode({"common_name": q})
        items.append({"section": "Create", "type": "action", "label": f"New SSL certificate: {q}", "meta": "Prefill common name", "url": reverse("ui:sslcerts_new") + f"?{cn_enc}"})
        t_enc = urlencode({"title": q})
        items.append({"section": "Create", "type": "action", "label": f"New doc: {q}", "meta": "Prefill title", "url": reverse("ui:documents_new") + f"?{t_enc}"})

        def add(obj_type: str, label: str, meta: str, url: str):
            section = {
                "asset": "Assets",
                "config": "Config Items",
                "doc": "Docs",
                "note": "Notes",
                "password": "Passwords",
                "checklist": "Checklists",
                "contact": "Contacts",
                "domain": "Domains",
                "sslcert": "SSL Certificates",
                "flex": "Flexible Assets",
            }.get(obj_type, "Results")
            items.append({"section": section, "type": obj_type, "label": label, "meta": meta, "url": url})

        for obj in Asset.objects.filter(organization=org, archived_at__isnull=True).filter(
            Q(name__icontains=q) | Q(serial_number__icontains=q) | Q(manufacturer__icontains=q) | Q(model__icontains=q)
        ).order_by("name")[:8]:
            add("asset", obj.name, obj.get_asset_type_display(), reverse("ui:asset_detail", kwargs={"asset_id": obj.id}))

        for obj in ConfigurationItem.objects.filter(organization=org, archived_at__isnull=True).filter(
            Q(name__icontains=q) | Q(hostname__icontains=q) | Q(primary_ip__icontains=q)
        ).order_by("name")[:8]:
            meta = obj.hostname or (str(obj.primary_ip) if obj.primary_ip else obj.get_ci_type_display())
            add("config", obj.name, meta, reverse("ui:config_item_detail", kwargs={"item_id": obj.id}))

        dqs = Document.objects.filter(organization=org, archived_at__isnull=True)
        if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
            dqs = dqs.filter(_visible_docs_q(request.user, org)).distinct()
        if _is_postgres():
            try:
                from django.contrib.postgres.search import SearchVector

                vector = SearchVector("title", weight="A") + SearchVector("body", weight="B")
                dqs2 = _fts_ranked(dqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "-updated_at")
            except Exception:
                dqs2 = dqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-updated_at")
        else:
            dqs2 = dqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-updated_at")
        for obj in dqs2[:8]:
            add("doc", obj.title, obj.updated_at.strftime("%Y-%m-%d"), reverse("ui:document_detail", kwargs={"document_id": obj.id}))

        nqs = _notes_qs_for_user(user=request.user, org=org)
        if _is_postgres():
            try:
                from django.contrib.postgres.search import SearchVector

                vector = SearchVector("title", weight="A") + SearchVector("body", weight="B")
                nqs2 = _fts_ranked(nqs, q=q, vector=vector, rank_field="_fts_rank").order_by("-_fts_rank", "-created_at")
            except Exception:
                nqs2 = nqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-created_at")
        else:
            nqs2 = nqs.filter(Q(title__icontains=q) | Q(body__icontains=q)).order_by("-created_at")
        for obj in nqs2[:8]:
            label = obj.title or f"Note {obj.id}"
            meta = obj.created_at.strftime("%Y-%m-%d")
            add("note", label, meta, reverse("ui:note_detail", kwargs={"note_id": obj.id}))

        pqs = PasswordEntry.objects.filter(organization=org, archived_at__isnull=True)
        if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
            pqs = pqs.filter(_visible_passwords_q(request.user, org)).distinct()
        for obj in pqs.filter(Q(name__icontains=q) | Q(username__icontains=q) | Q(url__icontains=q) | Q(notes__icontains=q)).order_by("name")[:8]:
            add("password", obj.name, obj.username or "", reverse("ui:password_detail", kwargs={"password_id": obj.id}))

        for obj in Contact.objects.filter(organization=org, archived_at__isnull=True).filter(
            Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q)
        ).order_by("last_name", "first_name")[:8]:
            add("contact", str(obj), obj.email or "", reverse("ui:contact_detail", kwargs={"contact_id": obj.id}))

        for obj in Domain.objects.filter(organization=org, archived_at__isnull=True).filter(
            Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q) | Q(notes__icontains=q)
        ).order_by("name")[:8]:
            meta = obj.expires_on.isoformat() if obj.expires_on else ""
            add("domain", obj.name, meta, reverse("ui:domain_detail", kwargs={"domain_id": obj.id}))

        for obj in SSLCertificate.objects.filter(organization=org, archived_at__isnull=True).filter(
            Q(common_name__icontains=q) | Q(subject_alt_names__icontains=q) | Q(issuer__icontains=q) | Q(notes__icontains=q)
        ).order_by("not_after", "common_name")[:8]:
            meta = obj.not_after.isoformat() if obj.not_after else ""
            add("sslcert", obj.common_name or f"Cert {obj.id}", meta, reverse("ui:sslcert_detail", kwargs={"sslcert_id": obj.id}))

        for obj in Checklist.objects.filter(organization=org, archived_at__isnull=True).filter(
            Q(name__icontains=q) | Q(description__icontains=q)
        ).order_by("-updated_at", "name")[:8]:
            add("checklist", obj.name, obj.updated_at.strftime("%Y-%m-%d"), reverse("ui:checklist_detail", kwargs={"checklist_id": obj.id}))

        for obj in FlexibleAsset.objects.filter(organization=org, archived_at__isnull=True).select_related("asset_type").filter(
            Q(name__icontains=q) | Q(notes__icontains=q)
        ).order_by("name")[:8]:
            add("flex", obj.name, obj.asset_type.name, reverse("ui:flex_asset_detail", kwargs={"type_id": obj.asset_type_id, "asset_id": obj.id}))

    # Keep response small and predictable.
    return JsonResponse({"q": q, "items": items[:50]})


@login_required
def note_detail(request: HttpRequest, note_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    note = get_object_or_404(Note, organization=org, id=note_id)

    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)
    if not can_admin:
        # Match Notes list behavior: do not reveal notes attached to restricted Docs/Passwords.
        if note.content_type_id and note.object_id:
            model_cls = note.content_type.model_class()
            if model_cls is Document:
                doc = Document.objects.filter(organization=org, id=int(note.object_id)).first()
                if doc and not _can_view_document(user=request.user, org=org, doc=doc):
                    raise PermissionDenied("Not allowed to view this note.")
            if model_cls is PasswordEntry:
                entry = PasswordEntry.objects.filter(organization=org, id=int(note.object_id)).first()
                if entry and not _can_view_password(user=request.user, org=org, entry=entry):
                    raise PermissionDenied("Not allowed to view this note.")

    attached_obj = note.content_object
    attached_url = None
    attached_label = None
    attached_ref_label = None
    if note.content_type_id and note.object_id:
        attached_ref_label = _human_ref_label(ct=note.content_type, oid=note.object_id)
    if attached_obj is not None:
        try:
            attached_url = _url_for_object_detail(attached_obj)
            attached_label = str(attached_obj)
        except Exception:
            attached_url = None
            attached_label = None

    return render(
        request,
        "ui/note_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Notes", reverse("ui:notes_list")), (note.title or f"Note {note.id}", None)),
            "note": note,
            "attached_url": attached_url,
            "attached_label": attached_label,
            "attached_ref_label": attached_ref_label,
        },
    )


@login_required
def settings_view(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)
    flash = None

    def _set_flash(title: str, body: str):
        nonlocal flash
        flash = {"title": title, "body": body}

    if request.method == "POST" and can_admin:
        action = (request.POST.get("_action") or "").strip()
        if action == "member_add":
            username = (request.POST.get("username") or "").strip()
            role = (request.POST.get("role") or "member").strip()
            role = role if role in {OrganizationMembership.ROLE_MEMBER, OrganizationMembership.ROLE_ADMIN, OrganizationMembership.ROLE_OWNER} else OrganizationMembership.ROLE_MEMBER
            User = get_user_model()
            u = User.objects.filter(username=username).first()
            if not u:
                _set_flash("Member not added", "User not found.")
            else:
                OrganizationMembership.objects.update_or_create(organization=org, user=u, defaults={"role": role})
                _audit_event(
                    request=request,
                    org=org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="core.OrganizationMembership",
                    object_pk=f"{org.id}:{u.id}",
                    summary=f"Added/updated member '{u.username}' with role '{role}'.",
                )
                _set_flash("Member added", f"Added '{u.username}' as {role}.")
            return redirect("ui:settings")

        if action == "member_set_role":
            mid = (request.POST.get("membership_id") or "").strip()
            role = (request.POST.get("role") or "member").strip()
            role = role if role in {OrganizationMembership.ROLE_MEMBER, OrganizationMembership.ROLE_ADMIN, OrganizationMembership.ROLE_OWNER} else OrganizationMembership.ROLE_MEMBER
            if mid.isdigit():
                m = OrganizationMembership.objects.filter(id=int(mid), organization=org).select_related("user").first()
                if m:
                    m.role = role
                    m.save(update_fields=["role"])
                    _audit_event(
                        request=request,
                        org=org,
                        action=AuditEvent.ACTION_UPDATE,
                        model="core.OrganizationMembership",
                        object_pk=str(m.id),
                        summary=f"Changed role for '{m.user.username}' to '{role}'.",
                    )
            return redirect("ui:settings")

        if action == "member_remove":
            mid = (request.POST.get("membership_id") or "").strip()
            if mid.isdigit():
                m = OrganizationMembership.objects.filter(id=int(mid), organization=org).select_related("user").first()
                if m:
                    _audit_event(
                        request=request,
                        org=org,
                        action=AuditEvent.ACTION_DELETE,
                        model="core.OrganizationMembership",
                        object_pk=str(m.id),
                        summary=f"Removed member '{m.user.username}' from org '{org.name}'.",
                    )
                    m.delete()
            return redirect("ui:settings")

    memberships = list(
        OrganizationMembership.objects.filter(organization=org).select_related("user").order_by("role", "user__username")[:5000]
    )

    return render(
        request,
        "ui/settings.html",
        {
            "org": org,
            "crumbs": _crumbs(("Org settings", None)),
            "memberships": memberships,
            "can_admin": can_admin,
            "is_superuser": bool(getattr(request.user, "is_superuser", False)),
            "flash": flash,
        },
    )


@login_required
def notifications_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    only_unread = (request.GET.get("unread") or "").strip() in {"1", "true", "yes", "on"}
    qs = Notification.objects.filter(organization=org, user=request.user).select_related("rule", "content_type").order_by("-created_at")
    if only_unread:
        qs = qs.filter(read_at__isnull=True)

    items = list(qs[:200])
    for n in items:
        ref_label = None
        ref_url = None
        if n.content_type_id and n.object_id:
            try:
                ref_label = _human_ref_label(ct=n.content_type, oid=n.object_id)
                # Only expose links for objects the current user can view.
                model_cls = n.content_type.model_class()
                if model_cls is Document:
                    obj = Document.objects.filter(organization=org, id=int(n.object_id)).first()
                    if obj and _can_view_document(user=request.user, org=org, doc=obj):
                        ref_url = _ui_object_url(n.content_type.app_label, n.content_type.model, n.object_id)
                elif model_cls is PasswordEntry:
                    obj = PasswordEntry.objects.filter(organization=org, id=int(n.object_id)).first()
                    if obj and _can_view_password(user=request.user, org=org, entry=obj):
                        ref_url = _ui_object_url(n.content_type.app_label, n.content_type.model, n.object_id)
                elif model_cls is Attachment:
                    obj = Attachment.objects.filter(organization=org, id=int(n.object_id)).select_related("content_type").first()
                    if obj and _can_view_attachment(request=request, org=org, a=obj):
                        ref_url = _ui_object_url(n.content_type.app_label, n.content_type.model, n.object_id)
                else:
                    ref_url = _ui_object_url(n.content_type.app_label, n.content_type.model, n.object_id)
            except Exception:
                ref_label = None
                ref_url = None
        setattr(n, "ref_label", ref_label)
        setattr(n, "ref_url", ref_url)
    unread_count = Notification.objects.filter(organization=org, user=request.user, read_at__isnull=True).count()
    return render(
        request,
        "ui/notifications_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Notifications", None)),
            "items": items,
            "only_unread": only_unread,
            "unread_count": unread_count,
        },
    )


@login_required
@require_POST
def notification_mark_read(request: HttpRequest, notification_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    n = get_object_or_404(Notification, organization=org, user=request.user, id=notification_id)
    from django.utils import timezone

    if n.read_at is None:
        n.read_at = timezone.now()
        n.save(update_fields=["read_at"])
    return _redirect_back(request, fallback_url=reverse("ui:notifications_list"))


@login_required
@require_POST
def notifications_mark_all_read(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    from django.utils import timezone

    Notification.objects.filter(organization=org, user=request.user, read_at__isnull=True).update(read_at=timezone.now())
    return _redirect_back(request, fallback_url=reverse("ui:notifications_list"))


@login_required
def workflows_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    qs = WorkflowRule.objects.filter(organization=org).order_by("kind", "name", "id")
    items = []
    for r in qs:
        days = None
        try:
            days = (r.params or {}).get("days")
        except Exception:
            days = None
        items.append(
            {
                "id": r.id,
                "name": r.name,
                "enabled": bool(r.enabled),
                "kind": r.get_kind_display(),
                "audience": r.get_audience_display(),
                "days": days,
                "run_interval_minutes": r.run_interval_minutes,
                "last_run_at": r.last_run_at,
                "last_run_ok": r.last_run_ok,
                "last_run_error": r.last_run_error,
                "detail_url": reverse("ui:workflow_rule_detail", kwargs={"rule_id": r.id}),
                "delete_url": reverse("ui:workflow_rule_delete", kwargs={"rule_id": r.id}),
            }
        )

    return render(
        request,
        "ui/workflows_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", None)),
            "items": items,
            "new_url": reverse("ui:workflow_rule_new"),
            "endpoints_url": reverse("ui:webhook_endpoints_list"),
            "runs_url": reverse("ui:workflow_runs_list"),
            "delivery_url": reverse("ui:workflow_delivery_attempts_list"),
        },
    )


@login_required
def workflow_runs_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    ok_raw = (request.GET.get("ok") or "").strip().lower()
    rule_id = (request.GET.get("rule_id") or "").strip()
    trigger = (request.GET.get("trigger") or "").strip().lower()

    qs = WorkflowRuleRun.objects.filter(organization=org).select_related("rule", "triggered_by_user").order_by("-started_at", "-id")
    if ok_raw in {"1", "true", "yes", "ok"}:
        qs = qs.filter(ok=True)
    elif ok_raw in {"0", "false", "no", "fail", "failed", "error"}:
        qs = qs.filter(ok=False)
    if rule_id.isdigit():
        qs = qs.filter(rule_id=int(rule_id))
    if trigger in {"worker", "manual", "ops"}:
        qs = qs.filter(triggered_by=trigger)

    items = list(qs[:200])
    rules = list(WorkflowRule.objects.filter(organization=org).order_by("name", "id")[:500])

    return render(
        request,
        "ui/workflow_runs_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), ("Runs", None)),
            "items": items,
            "rules": rules,
            "ok": ok_raw,
            "rule_id": rule_id,
            "trigger": trigger,
            "delivery_url": reverse("ui:workflow_delivery_attempts_list"),
        },
    )


@login_required
def workflow_delivery_attempts_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    ok_raw = (request.GET.get("ok") or "").strip().lower()
    kind = (request.GET.get("kind") or "").strip().lower()
    endpoint_id = (request.GET.get("endpoint_id") or "").strip()

    qs = (
        NotificationDeliveryAttempt.objects.select_related("notification", "endpoint", "notification__user", "notification__rule")
        .filter(notification__organization=org)
        .order_by("-attempted_at", "-id")
    )
    if ok_raw in {"1", "true", "yes", "ok"}:
        qs = qs.filter(ok=True)
    elif ok_raw in {"0", "false", "no", "fail", "failed", "error"}:
        qs = qs.filter(ok=False)
    if kind in {"email", "webhook"}:
        qs = qs.filter(kind=kind)
    if endpoint_id.isdigit():
        qs = qs.filter(endpoint_id=int(endpoint_id))

    items = list(qs[:200])
    endpoints = list(WebhookEndpoint.objects.filter(organization=org).order_by("name", "id")[:200])

    return render(
        request,
        "ui/workflow_delivery_attempts_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), ("Delivery", None)),
            "items": items,
            "endpoints": endpoints,
            "ok": ok_raw,
            "kind": kind,
            "endpoint_id": endpoint_id,
            "runs_url": reverse("ui:workflow_runs_list"),
        },
    )


@login_required
def workflow_rule_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    if request.method == "POST":
        form = WorkflowRuleForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:workflow_rule_detail", rule_id=obj.id)
    else:
        form = WorkflowRuleForm(org=org)
    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), ("New", None)),
            "title": "New workflow rule",
            "form": form,
        },
    )


@login_required
def workflow_rule_detail(request: HttpRequest, rule_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    rule = get_object_or_404(WorkflowRule, organization=org, id=rule_id)
    notice = None

    if request.method == "POST" and request.POST.get("_action") == "run_now":
        try:
            res = run_rule(rule, triggered_by=WorkflowRuleRun.TRIGGER_MANUAL, triggered_by_user=request.user)
            if res.ok:
                notice = {"title": "Rule ran", "body": f"Created {int(res.notifications_created or 0)} notification(s)."}
            else:
                notice = {"title": "Rule did not run", "body": str(res.error or "unknown")}
        except Exception as e:
            notice = {"title": "Run failed", "body": str(e)}
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_CREATE,
            model="workflows.WorkflowRuleRun",
            object_pk=str(rule.id),
            summary=f"Manual workflow run executed for rule '{rule.name}'.",
        )
        # Refresh rule status fields.
        rule.refresh_from_db()

    if request.method == "POST" and request.POST.get("_action") == "save":
        form = WorkflowRuleForm(request.POST, instance=rule, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:workflow_rule_detail", rule_id=rule.id)
    else:
        form = WorkflowRuleForm(instance=rule, org=org)

    days = None
    try:
        days = (rule.params or {}).get("days")
    except Exception:
        days = None

    recent_runs = list(
        WorkflowRuleRun.objects.filter(organization=org, rule=rule).select_related("triggered_by_user").order_by("-started_at", "-id")[:15]
    )
    recent_notifications = list(
        Notification.objects.filter(organization=org, rule=rule).select_related("user").order_by("-created_at", "-id")[:12]
    )

    return render(
        request,
        "ui/workflow_rule_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), (rule.name, None)),
            "rule": rule,
            "days": days,
            "form": form,
            "notice": notice,
            "recent_runs": recent_runs,
            "recent_notifications": recent_notifications,
            "runs_url": reverse("ui:workflow_runs_list") + "?" + urlencode({"rule_id": str(rule.id)}),
            "delivery_url": reverse("ui:workflow_delivery_attempts_list"),
        },
    )


@login_required
def workflow_rule_delete(request: HttpRequest, rule_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    rule = get_object_or_404(WorkflowRule, organization=org, id=rule_id)
    cancel = reverse("ui:workflow_rule_detail", kwargs={"rule_id": rule.id})
    redirect_url = reverse("ui:workflows_list")

    def _go():
        rule.delete()

    warning = "Existing notifications will remain. You can recreate the rule later."
    return _confirm_delete(
        request,
        org=org,
        kind="workflow rule",
        label=str(rule),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Delete",
        sub=None,
        on_confirm=_go,
    )


@login_required
def webhook_endpoints_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    qs = WebhookEndpoint.objects.filter(organization=org).order_by("-enabled", "name", "id")
    items = list(qs[:200])
    return render(
        request,
        "ui/webhook_endpoints_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), ("Webhook endpoints", None)),
            "items": items,
            "new_url": reverse("ui:webhook_endpoint_new"),
        },
    )


@login_required
def webhook_endpoint_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    if request.method == "POST":
        form = WebhookEndpointForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:webhook_endpoint_detail", endpoint_id=obj.id)
    else:
        form = WebhookEndpointForm(org=org)

    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), ("Webhook endpoints", reverse("ui:webhook_endpoints_list")), ("New", None)),
            "title": "New webhook endpoint",
            "form": form,
        },
    )


@login_required
def webhook_endpoint_detail(request: HttpRequest, endpoint_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    ep = get_object_or_404(WebhookEndpoint, organization=org, id=endpoint_id)
    if request.method == "POST":
        form = WebhookEndpointForm(request.POST, instance=ep, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:webhook_endpoint_detail", endpoint_id=ep.id)
    else:
        form = WebhookEndpointForm(instance=ep, org=org)

    sample_payload = {
        "id": 123,
        "organization_id": org.id,
        "user_id": request.user.id,
        "level": "warn",
        "title": "Example notification",
        "body": "This is a sample payload that HomeGlue sends.",
        "rule_id": None,
        "ref": None,
        "read_at": None,
        "created_at": timezone.now().isoformat(),
    }
    import json

    sample_payload_json = json.dumps(sample_payload, indent=2, sort_keys=True)

    recent_attempts = list(
        NotificationDeliveryAttempt.objects.select_related("notification", "notification__user")
        .filter(notification__organization=org, endpoint=ep)
        .order_by("-attempted_at", "-id")[:20]
    )

    return render(
        request,
        "ui/webhook_endpoint_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Workflows", reverse("ui:workflows_list")), ("Webhook endpoints", reverse("ui:webhook_endpoints_list")), (ep.name, None)),
            "endpoint": ep,
            "form": form,
            "delete_url": reverse("ui:webhook_endpoint_delete", kwargs={"endpoint_id": ep.id}),
            "sample_payload_json": sample_payload_json,
            "recent_attempts": recent_attempts,
            "delivery_url": reverse("ui:workflow_delivery_attempts_list") + "?" + urlencode({"endpoint_id": str(ep.id)}),
        },
    )


@login_required
def webhook_endpoint_delete(request: HttpRequest, endpoint_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    ep = get_object_or_404(WebhookEndpoint, organization=org, id=endpoint_id)
    cancel = reverse("ui:webhook_endpoint_detail", kwargs={"endpoint_id": ep.id})
    redirect_url = reverse("ui:webhook_endpoints_list")

    def _go():
        ep.delete()

    warning = "Existing delivery attempts will remain. New notifications will stop posting here."
    return _confirm_delete(
        request,
        org=org,
        kind="webhook endpoint",
        label=str(ep),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Delete",
        sub=None,
        on_confirm=_go,
    )


@login_required
def wiki_index(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    nav_ctx = _wiki_nav_context(active_slug=None, q=q, page_view_name="ui:wiki_page")
    pages = nav_ctx["wiki_pages"]
    pages_by_slug = nav_ctx["wiki_pages_by_slug"]

    results = []
    if q:
        q_lower = q.lower()
        for p in pages:
            try:
                md = p["path"].read_text(encoding="utf-8")
            except Exception:
                continue
            lines = md.splitlines()
            matches = [ln for ln in lines if q_lower in ln.lower()]
            if not matches:
                continue
            snippet = ""
            for ln in matches[:3]:
                s = (ln or "").strip()
                if not s or s.startswith("#"):
                    continue
                snippet = s[:220]
                break
            results.append({"slug": p["slug"], "title": p["title"], "url": p["url"], "count": len(matches), "snippet": snippet})
        results.sort(key=lambda r: (-int(r["count"]), str(r["title"]).lower()))

    home_slug = nav_ctx["wiki_home_slug"]
    home_title = nav_ctx["wiki_home_title"]
    home_body_html = ""
    if not q and home_slug and home_slug in pages_by_slug:
        try:
            md = pages_by_slug[home_slug]["path"].read_text(encoding="utf-8")
            home_body_html = _render_markdown_simple(md, page_view_name="ui:wiki_page")
        except Exception:
            home_body_html = ""

    return render(
        request,
        "ui/wiki_index.html",
        {
            "org": org,
            "crumbs": _crumbs(("Wiki", None)),
            "wiki_q": q,
            "wiki_nav": nav_ctx["wiki_nav"],
            "home_title": home_title or "Wiki",
            "home_body_html": home_body_html,
            "results": results,
        },
    )


@login_required
def wiki_page(request: HttpRequest, slug: str) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    slug = (slug or "").strip()
    if not _WIKI_SLUG_RE.match(slug):
        raise PermissionDenied("Invalid wiki page.")

    path = _wiki_root() / f"{slug}.md"
    if not path.exists():
        raise PermissionDenied("Wiki page not found.")

    md = path.read_text(encoding="utf-8")
    body_html = _render_markdown_simple(md, page_view_name="ui:wiki_page")
    title = slug
    for line in md.splitlines():
        if line.startswith("# "):
            title = line[2:].strip() or slug
            break

    return render(
        request,
        "ui/wiki_page.html",
        {
            "org": org,
            "crumbs": _crumbs(("Wiki", reverse("ui:wiki_index")), (title, None)),
            "title": title,
            "body_html": body_html,
            "wiki_q": "",
            "wiki_nav": _wiki_nav_context(active_slug=slug, q="", page_view_name="ui:wiki_page")["wiki_nav"],
        },
    )


def public_wiki_index(request: HttpRequest) -> HttpResponse:
    """
    Public (no-login) read-only view of the shipped documentation wiki.
    """

    q = (request.GET.get("q") or "").strip()
    nav_ctx = _wiki_nav_context(active_slug=None, q=q, page_view_name="public_wiki:wiki_page")
    pages = nav_ctx["wiki_pages"]
    pages_by_slug = nav_ctx["wiki_pages_by_slug"]

    results = []
    if q:
        q_lower = q.lower()
        for p in pages:
            try:
                md = p["path"].read_text(encoding="utf-8")
            except Exception:
                continue
            lines = md.splitlines()
            matches = [ln for ln in lines if q_lower in ln.lower()]
            if not matches:
                continue
            snippet = ""
            for ln in matches[:3]:
                s = (ln or "").strip()
                if not s or s.startswith("#"):
                    continue
                snippet = s[:220]
                break
            results.append({"slug": p["slug"], "title": p["title"], "url": p["url"], "count": len(matches), "snippet": snippet})
        results.sort(key=lambda r: (-int(r["count"]), str(r["title"]).lower()))

    home_slug = nav_ctx["wiki_home_slug"]
    home_title = nav_ctx["wiki_home_title"]
    home_body_html = ""
    if not q and home_slug and home_slug in pages_by_slug:
        try:
            md = pages_by_slug[home_slug]["path"].read_text(encoding="utf-8")
            home_body_html = _render_markdown_simple(md, page_view_name="public_wiki:wiki_page")
        except Exception:
            home_body_html = ""

    return render(
        request,
        "ui/wiki_public_index.html",
        {
            "org": None,
            "crumbs": _crumbs(("Wiki", None)),
            "wiki_q": q,
            "wiki_nav": nav_ctx["wiki_nav"],
            "home_title": home_title or "Wiki",
            "home_body_html": home_body_html,
            "results": results,
        },
    )


def public_wiki_page(request: HttpRequest, slug: str) -> HttpResponse:
    """
    Public (no-login) read-only wiki page.
    """

    slug = (slug or "").strip()
    if not _WIKI_SLUG_RE.match(slug):
        raise PermissionDenied("Invalid wiki page.")

    path = _wiki_root() / f"{slug}.md"
    if not path.exists():
        raise PermissionDenied("Wiki page not found.")

    md = path.read_text(encoding="utf-8")
    body_html = _render_markdown_simple(md, page_view_name="public_wiki:wiki_page")
    title = slug
    for line in md.splitlines():
        if line.startswith("# "):
            title = line[2:].strip() or slug
            break

    return render(
        request,
        "ui/wiki_public_page.html",
        {
            "org": None,
            "crumbs": _crumbs(("Wiki", reverse("public_wiki:wiki_index")), (title, None)),
            "title": title,
            "body_html": body_html,
            "wiki_q": "",
            "wiki_nav": _wiki_nav_context(active_slug=slug, q="", page_view_name="public_wiki:wiki_page")["wiki_nav"],
        },
    )


@login_required
@require_POST
def markdown_preview(request: HttpRequest) -> JsonResponse:
    """
    Preview endpoint for markdown editors (Docs, Notes, etc.).
    Uses the same safe renderer everywhere.
    """

    require_current_org(request)
    text = (request.POST.get("text") or "").strip()
    return JsonResponse({"html": render_markdown(text)})


@login_required
def saved_views_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    qs = SavedView.objects.filter(organization=org).order_by("model_key", "name")

    items = []
    for sv in qs:
        list_url_name = _MODEL_KEY_TO_LIST_URL.get(sv.model_key)
        apply_url = None
        if list_url_name:
            apply_url = reverse(list_url_name) + f"?view={sv.id}"
        q = ""
        try:
            q = (sv.params or {}).get("q") or ""
        except Exception:
            q = ""
        items.append(
            {
                "id": sv.id,
                "name": sv.name,
                "model_key": sv.model_key,
                "model_label": sv.get_model_key_display(),
                "q": q,
                "apply_url": apply_url,
                "delete_url": reverse("ui:saved_view_delete", kwargs={"view_id": sv.id}),
            }
        )

    return render(
        request,
        "ui/saved_views_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Saved Views", None)),
            "items": items,
        },
    )


@login_required
def saved_view_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    model_key = (request.GET.get("model_key") or request.POST.get("model_key") or "").strip()
    next_url = (request.GET.get("next") or request.POST.get("next") or "").strip()
    q = (request.GET.get("q") or request.POST.get("q") or "").strip()
    params_json = (request.GET.get("params_json") or request.POST.get("params_json") or "").strip()

    if model_key not in _MODEL_KEY_TO_LIST_URL:
        raise PermissionDenied("Unknown view type.")

    model_label = dict(SavedView.KEY_CHOICES).get(model_key, model_key)

    if request.method == "POST":
        form = SavedViewForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.model_key = model_key
            params = {"q": q} if q else {}
            if params_json:
                try:
                    parsed = json.loads(params_json)
                    if isinstance(parsed, dict):
                        params = {str(k): str(v) for k, v in parsed.items() if str(v or "").strip()}
                except Exception:
                    pass
            obj.params = params
            obj.created_by = request.user
            obj.save()
            return _redirect_back(request, fallback_url=reverse("ui:saved_views_list"))
    else:
        form = SavedViewForm(org=org)

    return render(
        request,
        "ui/saved_view_new.html",
        {
            "org": org,
            "crumbs": _crumbs(("Saved Views", reverse("ui:saved_views_list")), ("New", None)),
            "title": "Save view",
            "form": form,
            "model_key": model_key,
            "model_label": model_label,
            "q": q,
            "next_url": next_url,
            "params_json": params_json,
        },
    )


@login_required
def saved_view_delete(request: HttpRequest, view_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    sv = get_object_or_404(SavedView, organization=org, id=view_id)
    cancel = reverse("ui:saved_views_list")
    redirect_url = cancel

    def _go():
        sv.delete()

    return _confirm_delete(
        request,
        org=org,
        kind="saved view",
        label=f"{sv.get_model_key_display()} / {sv.name}",
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        on_confirm=_go,
    )

@login_required
def custom_fields_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    qs = (
        CustomField.objects.filter(organization=org)
        .select_related("content_type", "flexible_asset_type")
        .order_by("content_type__app_label", "content_type__model", "flexible_asset_type__name", "sort_order", "name")
    )
    fields = list(qs)
    for f in fields:
        label = _human_ct_label(f.content_type)
        if f.flexible_asset_type_id:
            label = f"{label} (Type: {f.flexible_asset_type.name})"
        setattr(f, "applies_to_label", label)
    return render(
        request,
        "ui/custom_fields_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Custom Fields", None)),
            "fields": fields,
            "custom_fields_new_url": reverse("ui:custom_fields_new"),
        },
    )


@login_required
def custom_fields_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    if request.method == "POST":
        form = CustomFieldForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:custom_field_detail", field_id=obj.id)
    else:
        form = CustomFieldForm(org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Custom Fields", reverse("ui:custom_fields_list")), ("New", None)), "title": "New custom field", "form": form},
    )


@login_required
def custom_field_detail(request: HttpRequest, field_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    field = get_object_or_404(CustomField.objects.select_related("content_type"), id=field_id, organization=org)
    if request.method == "POST":
        form = CustomFieldForm(request.POST, instance=field, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:custom_field_detail", field_id=field.id)
    else:
        form = CustomFieldForm(instance=field, org=org)
    return render(
        request,
        "ui/custom_field_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Custom Fields", reverse("ui:custom_fields_list")), (field.name, None)),
            "field": field,
            "applies_to_label": _human_ct_label(field.content_type),
            "form": form,
        },
    )


@login_required
def custom_field_delete(request: HttpRequest, field_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    field = get_object_or_404(CustomField, id=field_id, organization=org)
    cancel = reverse("ui:custom_field_detail", kwargs={"field_id": field.id})
    redirect_url = reverse("ui:custom_fields_list")

    def _go():
        # Values cascade via FK.
        field.delete()

    warning = "All values for this field will be deleted."
    return _confirm_delete(
        request,
        org=org,
        kind="custom field",
        label=f"{field.name} ({field.key})",
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


@login_required
def locations_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_LOCATION, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = Location.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(address__icontains=q))
    locs = list(qs[:200])
    return render(
        request,
        "ui/locations_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Locations", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "locations": locs,
            "locations_new_url": reverse("ui:locations_new"),
            "export_url": reverse("ui:locations_export") + _qs_suffix(request),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=Location, ids=[l.id for l in locs]),
            "ref_prefix": _ref_prefix_for_model(Location),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_LOCATION),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_LOCATION, q=q),
            "clear_view_url": reverse("ui:locations_list"),
        },
    )

@login_required
def locations_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_LOCATION, q=q)
    qs = Location.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(address__icontains=q))
    rows = []
    for l in qs[:5000]:
        rows.append([l.name or "", l.address or ""])
    return _csv_http_response(filename=f"{org.name}-locations.csv", header=["name", "address"], rows=rows)

@login_required
@require_POST
def locations_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=Location,
        base_qs=Location.objects.filter(organization=org),
        list_url_name="ui:locations_list",
        supports_tags=False,
    )


@login_required
def locations_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        address = (request.POST.get("address") or "").strip()
        if name:
            loc = Location.objects.create(organization=org, name=name, address=address)
            return redirect("ui:location_detail", location_id=loc.id)
    return render(
        request,
        "ui/location_new.html",
        {"org": org, "crumbs": _crumbs(("Locations", reverse("ui:locations_list")), ("New", None)), "title": "New location"},
    )


@login_required
def location_detail(request: HttpRequest, location_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    loc = get_object_or_404(Location, id=location_id, organization=org)
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=loc, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:location_detail", location_id=loc.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=loc)
        return redirect(request.get_full_path())

    if request.method == "POST":
        loc.name = (request.POST.get("name") or "").strip()
        loc.address = (request.POST.get("address") or "").strip()
        if loc.name:
            loc.save(update_fields=["name", "address"])
            return redirect("ui:location_detail", location_id=loc.id)
    edit_mode = _is_edit_mode(request)
    relationships = _relationships_for_object(org=org, obj=loc, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/location_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Locations", reverse("ui:locations_list")), (loc.name, None)),
            "location": loc,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:location_detail", kwargs={"location_id": loc.id}) + "?edit=1",
            "view_url": reverse("ui:location_detail", kwargs={"location_id": loc.id}),
            "can_admin": can_admin,
            "attachments": _attachments_for_object(org=org, obj=loc),
            "notes": _notes_for_object(org=org, obj=loc),
            "note_ref": _ref_for_obj(loc),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=Location),
            "custom_values": _custom_field_values_for_object(org=org, obj=loc),
            "activity": _activity_for_object(org=org, model_cls=Location, obj_id=loc.id),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(loc)}",
        },
    )


@login_required
def location_delete(request: HttpRequest, location_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    loc = get_object_or_404(Location, id=location_id, organization=org)
    cancel = reverse("ui:location_detail", kwargs={"location_id": loc.id})
    redirect_url = reverse("ui:locations_list")

    def _go():
        if loc.archived_at is None:
            loc.archived_at = timezone.now()
            loc.save(update_fields=["archived_at"])

    return _confirm_delete(
        request,
        org=org,
        kind="location",
        label=str(loc),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )

@login_required
def contacts_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_CONTACT, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = Contact.objects.filter(organization=org).order_by("last_name", "first_name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q))
    contacts = list(qs[:200])
    return render(
        request,
        "ui/contacts_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Contacts", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "contacts": contacts,
            "contacts_new_url": reverse("ui:contacts_new"),
            "export_url": reverse("ui:contacts_export") + _qs_suffix(request),
            "import_url": reverse("ui:contacts_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=Contact, ids=[c.id for c in contacts]),
            "ref_prefix": _ref_prefix_for_model(Contact),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_CONTACT),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_CONTACT, q=q),
            "clear_view_url": reverse("ui:contacts_list"),
        },
    )

@login_required
def contacts_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert strategy:
    - If email is present: upsert by (org, email) (case-insensitive match).
    - If email is blank: create a new contact (no dedupe).
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"first_name", "last_name", "email", "phone", "title"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: first_name,last_name,email,phone,title")
            else:
                for idx, row in enumerate(reader, start=2):
                    try:
                        first = (row.get("first_name") or "").strip()
                        last = (row.get("last_name") or "").strip()
                        email = (row.get("email") or "").strip()
                        phone = (row.get("phone") or "").strip()
                        title = (row.get("title") or "").strip()

                        if not first and not last and not email:
                            errors.append(f"Line {idx}: missing first_name/last_name/email")
                            continue

                        obj = None
                        if email:
                            obj = Contact.objects.filter(organization=org, email__iexact=email).first()

                        if not obj:
                            Contact.objects.create(
                                organization=org,
                                first_name=first or (email.split("@", 1)[0] if email else "Unknown"),
                                last_name=last,
                                email=email,
                                phone=phone,
                                title=title,
                            )
                            created += 1
                        else:
                            changed = False
                            for field, val in [
                                ("first_name", first or obj.first_name),
                                ("last_name", last),
                                ("phone", phone),
                                ("title", title),
                            ]:
                                if getattr(obj, field) != val:
                                    setattr(obj, field, val)
                                    changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/contacts_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Contacts", reverse("ui:contacts_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/contacts_import.html",
        {"org": org, "crumbs": _crumbs(("Contacts", reverse("ui:contacts_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )

@login_required
def contacts_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_CONTACT, q=q)
    qs = Contact.objects.filter(organization=org).order_by("last_name", "first_name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q))
    rows = []
    for c in qs[:5000]:
        rows.append([c.first_name or "", c.last_name or "", c.email or "", c.phone or "", c.title or ""])
    return _csv_http_response(
        filename=f"{org.name}-contacts.csv",
        header=["first_name", "last_name", "email", "phone", "title"],
        rows=rows,
    )

@login_required
@require_POST
def contacts_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=Contact,
        base_qs=Contact.objects.filter(organization=org),
        list_url_name="ui:contacts_list",
        supports_tags=True,
    )


@login_required
def contacts_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = ContactForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            form.save_m2m()
            return redirect("ui:contact_detail", contact_id=obj.id)
    else:
        form = ContactForm(org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Contacts", reverse("ui:contacts_list")), ("New", None)), "title": "New contact", "form": form},
    )


@login_required
def contact_detail(request: HttpRequest, contact_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    contact = get_object_or_404(Contact, id=contact_id, organization=org)
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=contact, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:contact_detail", contact_id=contact.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=contact)
        return redirect(request.get_full_path())

    if request.method == "POST":
        form = ContactForm(request.POST, instance=contact, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:contact_detail", contact_id=contact.id)
    else:
        form = ContactForm(instance=contact, org=org)
    relationships = _relationships_for_object(org=org, obj=contact, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    edit_mode = _is_edit_mode(request)
    return render(
        request,
        "ui/contact_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Contacts", reverse("ui:contacts_list")), (str(contact), None)),
            "contact": contact,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:contact_detail", kwargs={"contact_id": contact.id}) + "?edit=1",
            "view_url": reverse("ui:contact_detail", kwargs={"contact_id": contact.id}),
            "can_admin": can_admin,
            "attachments": _attachments_for_object(org=org, obj=contact),
            "notes": _notes_for_object(org=org, obj=contact),
            "note_ref": _ref_for_obj(contact),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=Contact),
            "custom_values": _custom_field_values_for_object(org=org, obj=contact),
            "activity": _activity_for_object(org=org, model_cls=Contact, obj_id=contact.id),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(contact)}",
        },
    )


@login_required
def contact_delete(request: HttpRequest, contact_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    contact = get_object_or_404(Contact, id=contact_id, organization=org)
    cancel = reverse("ui:contact_detail", kwargs={"contact_id": contact.id})
    redirect_url = reverse("ui:contacts_list")

    def _go():
        if contact.archived_at is None:
            contact.archived_at = timezone.now()
            contact.save(update_fields=["archived_at"])

    return _confirm_delete(
        request,
        org=org,
        kind="contact",
        label=str(contact),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )

@login_required
def config_items_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_CONFIG_ITEM, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = ConfigurationItem.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(hostname__icontains=q) | Q(primary_ip__icontains=q))
    items = list(qs[:200])
    return render(
        request,
        "ui/config_items_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Config Items", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "items": items,
            "config_items_new_url": reverse("ui:config_items_new"),
            "export_url": reverse("ui:config_items_export") + _qs_suffix(request),
            "import_url": reverse("ui:config_items_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=ConfigurationItem, ids=[i.id for i in items]),
            "ref_prefix": _ref_prefix_for_model(ConfigurationItem),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_CONFIG_ITEM),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_CONFIG_ITEM, q=q),
            "clear_view_url": reverse("ui:config_items_list"),
        },
    )

@login_required
def config_items_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert by (org, name).
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"name", "type", "hostname", "primary_ip", "operating_system"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: name,type,hostname,primary_ip,operating_system")
            else:
                type_map = {k: v for (k, v) in ConfigurationItem.TYPE_CHOICES}
                type_by_display = {str(lbl).strip().lower(): key for (key, lbl) in ConfigurationItem.TYPE_CHOICES}

                for idx, row in enumerate(reader, start=2):
                    try:
                        name = (row.get("name") or "").strip()
                        if not name:
                            errors.append(f"Line {idx}: missing name")
                            continue

                        t_raw = (row.get("type") or "").strip()
                        ci_type = ConfigurationItem.TYPE_OTHER
                        if t_raw:
                            t_key = t_raw.strip().lower()
                            if t_key in type_map:
                                ci_type = t_key
                            elif t_key in type_by_display:
                                ci_type = type_by_display[t_key]
                            else:
                                errors.append(f"Line {idx}: unknown type '{t_raw}' (defaulted to Other)")
                                ci_type = ConfigurationItem.TYPE_OTHER

                        hostname = (row.get("hostname") or "").strip()
                        ip_raw = (row.get("primary_ip") or "").strip()
                        primary_ip = None
                        if ip_raw:
                            # Let Django field validation handle it on save; we just pass the string.
                            primary_ip = ip_raw
                        operating_system = (row.get("operating_system") or "").strip()

                        obj, was_created = ConfigurationItem.objects.get_or_create(
                            organization=org,
                            name=name,
                            defaults={
                                "ci_type": ci_type,
                                "hostname": hostname,
                                "primary_ip": primary_ip,
                                "operating_system": operating_system,
                            },
                        )
                        if was_created:
                            created += 1
                        else:
                            changed = False
                            for field, val in [
                                ("ci_type", ci_type),
                                ("hostname", hostname),
                                ("primary_ip", primary_ip),
                                ("operating_system", operating_system),
                            ]:
                                if getattr(obj, field) != val:
                                    setattr(obj, field, val)
                                    changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/config_items_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Config Items", reverse("ui:config_items_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/config_items_import.html",
        {"org": org, "crumbs": _crumbs(("Config Items", reverse("ui:config_items_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )

@login_required
def config_items_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_CONFIG_ITEM, q=q)
    qs = ConfigurationItem.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(hostname__icontains=q) | Q(primary_ip__icontains=q))
    rows = []
    for i in qs[:5000]:
        rows.append(
            [
                i.name or "",
                i.get_ci_type_display() or "",
                i.hostname or "",
                str(i.primary_ip) if i.primary_ip else "",
                i.operating_system or "",
            ]
        )
    return _csv_http_response(
        filename=f"{org.name}-config-items.csv",
        header=["name", "type", "hostname", "primary_ip", "operating_system"],
        rows=rows,
    )

@login_required
@require_POST
def config_items_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=ConfigurationItem,
        base_qs=ConfigurationItem.objects.filter(organization=org),
        list_url_name="ui:config_items_list",
        supports_tags=True,
    )


@login_required
def config_items_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = ConfigurationItemForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            form.save_m2m()
            return redirect("ui:config_item_detail", item_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        form = ConfigurationItemForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Config Items", reverse("ui:config_items_list")), ("New", None)), "title": "New config item", "form": form},
    )


@login_required
def config_item_detail(request: HttpRequest, item_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    item = get_object_or_404(ConfigurationItem, id=item_id, organization=org)
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=item, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:config_item_detail", item_id=item.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=item)
        return redirect(request.get_full_path())

    if request.method == "POST":
        form = ConfigurationItemForm(request.POST, instance=item, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:config_item_detail", item_id=item.id)
    else:
        form = ConfigurationItemForm(instance=item, org=org)
    relationships = _relationships_for_object(org=org, obj=item, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    edit_mode = _is_edit_mode(request)
    return render(
        request,
        "ui/config_item_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Config Items", reverse("ui:config_items_list")), (item.name, None)),
            "item": item,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:config_item_detail", kwargs={"item_id": item.id}) + "?edit=1",
            "view_url": reverse("ui:config_item_detail", kwargs={"item_id": item.id}),
            "can_admin": can_admin,
            "proxmox_guest": getattr(item, "proxmox_guest", None),
            "attachments": _attachments_for_object(org=org, obj=item),
            "notes": _notes_for_object(org=org, obj=item),
            "note_ref": _ref_for_obj(item),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=ConfigurationItem),
            "custom_values": _custom_field_values_for_object(org=org, obj=item),
            "activity": _activity_for_object(org=org, model_cls=ConfigurationItem, obj_id=item.id),
            "versions": _versions_for_object(org=org, obj=item, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(item)}",
        },
    )


@login_required
def config_item_delete(request: HttpRequest, item_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    item = get_object_or_404(ConfigurationItem, id=item_id, organization=org)
    cancel = reverse("ui:config_item_detail", kwargs={"item_id": item.id})
    redirect_url = reverse("ui:config_items_list")

    def _go():
        if item.archived_at is None:
            item.archived_at = timezone.now()
            item.save(update_fields=["archived_at"])

    return _confirm_delete(
        request,
        org=org,
        kind="config item",
        label=str(item),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )

@login_required
def assets_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_ASSET, q=q)

    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = Asset.objects.select_related("location").filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(serial_number__icontains=q) | Q(manufacturer__icontains=q) | Q(model__icontains=q))

    assets = list(qs[:200])
    return render(
        request,
        "ui/assets_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Assets", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "assets": assets,
            "assets_new_url": reverse("ui:assets_new"),
            "export_url": reverse("ui:assets_export") + _qs_suffix(request),
            "import_url": reverse("ui:assets_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=Asset, ids=[a.id for a in assets]),
            "ref_prefix": _ref_prefix_for_model(Asset),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_ASSET),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_ASSET, q=q),
            "clear_view_url": reverse("ui:assets_list"),
        },
    )

@login_required
def assets_import(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"name", "type", "manufacturer", "model", "serial_number", "location"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: name,type,manufacturer,model,serial_number,location")
            else:
                type_map = {k: v for (k, v) in Asset.TYPE_CHOICES}
                type_by_display = {str(lbl).strip().lower(): key for (key, lbl) in Asset.TYPE_CHOICES}

                for idx, row in enumerate(reader, start=2):  # header is line 1
                    try:
                        name = (row.get("name") or "").strip()
                        if not name:
                            errors.append(f"Line {idx}: missing name")
                            continue

                        t_raw = (row.get("type") or "").strip()
                        asset_type = Asset.TYPE_OTHER
                        if t_raw:
                            t_key = t_raw.strip().lower()
                            if t_key in type_map:
                                asset_type = t_key
                            elif t_key in type_by_display:
                                asset_type = type_by_display[t_key]
                            else:
                                errors.append(f"Line {idx}: unknown type '{t_raw}' (defaulted to Other)")
                                asset_type = Asset.TYPE_OTHER

                        manufacturer = (row.get("manufacturer") or "").strip()
                        model = (row.get("model") or "").strip()
                        serial_number = (row.get("serial_number") or "").strip()
                        loc_name = (row.get("location") or "").strip()

                        loc = None
                        if loc_name:
                            loc, _ = Location.objects.get_or_create(organization=org, name=loc_name, defaults={"address": ""})

                        obj, was_created = Asset.objects.get_or_create(
                            organization=org,
                            name=name,
                            defaults={
                                "asset_type": asset_type,
                                "manufacturer": manufacturer,
                                "model": model,
                                "serial_number": serial_number,
                                "location": loc,
                            },
                        )
                        if was_created:
                            created += 1
                        else:
                            changed = False
                            for field, val in [
                                ("asset_type", asset_type),
                                ("manufacturer", manufacturer),
                                ("model", model),
                                ("serial_number", serial_number),
                            ]:
                                if getattr(obj, field) != val:
                                    setattr(obj, field, val)
                                    changed = True
                            if getattr(obj, "location_id", None) != (loc.id if loc else None):
                                obj.location = loc
                                changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/assets_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Assets", reverse("ui:assets_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/assets_import.html",
        {"org": org, "crumbs": _crumbs(("Assets", reverse("ui:assets_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )

@login_required
def assets_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_ASSET, q=q)
    qs = Asset.objects.select_related("location").filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(serial_number__icontains=q) | Q(manufacturer__icontains=q) | Q(model__icontains=q))
    rows = []
    for a in qs[:5000]:
        rows.append(
            [
                a.name or "",
                a.get_asset_type_display() or "",
                a.manufacturer or "",
                a.model or "",
                a.serial_number or "",
                a.location.name if a.location_id else "",
            ]
        )
    return _csv_http_response(
        filename=f"{org.name}-assets.csv",
        header=["name", "type", "manufacturer", "model", "serial_number", "location"],
        rows=rows,
    )

@login_required
@require_POST
def assets_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=Asset,
        base_qs=Asset.objects.filter(organization=org),
        list_url_name="ui:assets_list",
        supports_tags=True,
    )


@login_required
def assets_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = AssetForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:asset_detail", asset_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        form = AssetForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Assets", reverse("ui:assets_list")), ("New", None)), "title": "New asset", "form": form},
    )


@login_required
def asset_detail(request: HttpRequest, asset_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    asset = get_object_or_404(Asset.objects.select_related("location"), id=asset_id, organization=org)
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=asset, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:asset_detail", asset_id=asset.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=asset)
        return redirect(request.get_full_path())

    if request.method == "POST":
        form = AssetForm(request.POST, instance=asset, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:asset_detail", asset_id=asset.id)
    else:
        form = AssetForm(instance=asset, org=org)

    related = _relationships_for_object(org=org, obj=asset, limit=50)
    related_view = _relationships_view(request=request, org=org, relationships=related)
    edit_mode = _is_edit_mode(request)

    return render(
        request,
        "ui/asset_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Assets", reverse("ui:assets_list")), (asset.name, None)),
            "asset": asset,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:asset_detail", kwargs={"asset_id": asset.id}) + "?edit=1",
            "view_url": reverse("ui:asset_detail", kwargs={"asset_id": asset.id}),
            "can_admin": can_admin,
            "relationships": related,
            "relationships_view": related_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(asset)}",
            "attachments": _attachments_for_object(org=org, obj=asset),
            "notes": _notes_for_object(org=org, obj=asset),
            "note_ref": _ref_for_obj(asset),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=Asset),
            "custom_values": _custom_field_values_for_object(org=org, obj=asset),
            "activity": _activity_for_object(org=org, model_cls=Asset, obj_id=asset.id),
            "versions": _versions_for_object(org=org, obj=asset, limit=20),
            "can_restore": _is_org_admin(request.user, org),
        },
    )


@login_required
def asset_delete(request: HttpRequest, asset_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    asset = get_object_or_404(Asset, id=asset_id, organization=org)
    cancel = reverse("ui:asset_detail", kwargs={"asset_id": asset.id})
    redirect_url = reverse("ui:assets_list")

    def _go():
        if asset.archived_at is None:
            asset.archived_at = timezone.now()
            asset.save(update_fields=["archived_at"])

    warning = "Relationships, notes, and attachments will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="asset",
        label=str(asset),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )

@login_required
def documents_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_DOCUMENT, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    folder_raw = (request.GET.get("folder") or "").strip()
    folder_id = int(folder_raw) if folder_raw.isdigit() else None
    current_folder = None
    if folder_id:
        current_folder = DocumentFolder.objects.select_related("parent").filter(organization=org, archived_at__isnull=True, id=int(folder_id)).first()
        if current_folder is None:
            raise PermissionDenied("Folder not found.")

    # In "file explorer" mode: list child folders + docs within the current folder.
    folder_qs = DocumentFolder.objects.filter(organization=org, archived_at__isnull=True, parent=current_folder).order_by("name")
    if q:
        folder_qs = folder_qs.filter(name__icontains=q)
    child_folders = list(folder_qs[:200])

    qs = Document.objects.filter(organization=org, folder=current_folder).select_related("template", "folder").order_by("-updated_at")
    qs = _filter_archived_qs(request, qs)
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_docs_q(request.user, org)).distinct()
    flagged_only = (request.GET.get("flagged") or "").strip() in {"1", "true", "yes", "on"}
    if flagged_only:
        qs = qs.filter(flagged_at__isnull=False)
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(body__icontains=q))
    docs = list(qs[:200])

    # Breadcrumbs + "Up" URL.
    if current_folder:
        folder_chain = _doc_folder_crumb_items(folder=current_folder)
        crumbs = _crumbs(("Docs", reverse("ui:documents_list")), *folder_chain)
        up_id = int(current_folder.parent_id) if current_folder.parent_id else None
        up_url = reverse("ui:documents_list") + (("?" + urlencode({"folder": up_id})) if up_id else "")
    else:
        crumbs = _crumbs(("Docs", None))
        up_url = None

    # Contextual new URLs.
    documents_new_url = reverse("ui:documents_new")
    if current_folder:
        documents_new_url = documents_new_url + "?" + urlencode({"folder": int(current_folder.id)})
    new_folder_url = reverse("ui:document_folder_new")
    if current_folder:
        new_folder_url = new_folder_url + "?" + urlencode({"parent": int(current_folder.id)})

    # For bulk "move to folder" selector: include all folders with a path label.
    all_folders = list(
        DocumentFolder.objects.filter(organization=org, archived_at__isnull=True).select_related("parent").order_by("parent_id", "name")[:5000]
    )
    folder_paths = _folder_path_map(folders=all_folders)
    folders_for_move = [{"id": f.id, "label": str(folder_paths.get(int(f.id), {}).get("path") or f.name)} for f in all_folders]

    # Toggle URLs for "Flagged" filter (preserve other params like q/view/archived).
    params = request.GET.copy()
    params["flagged"] = "1"
    flagged_url = request.path + "?" + params.urlencode()
    params2 = request.GET.copy()
    params2.pop("flagged", None)
    all_url = request.path + (("?" + params2.urlencode()) if params2 else "")

    return render(
        request,
        "ui/documents_list.html",
        {
            "org": org,
            "crumbs": crumbs,
            "q": q,
            "current_folder": current_folder,
            "child_folders": child_folders,
            "up_url": up_url,
            "flagged_only": flagged_only,
            "flagged_url": flagged_url,
            "all_url": all_url,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "documents": docs,
            "documents_new_url": documents_new_url,
            "new_folder_url": new_folder_url,
            "folders_url": reverse("ui:document_folders_list"),
            "export_url": reverse("ui:documents_export") + _qs_suffix(request),
            "import_url": reverse("ui:documents_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=Document, ids=[d.id for d in docs]),
            "ref_prefix": _ref_prefix_for_model(Document),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "folders_for_move": folders_for_move,
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_DOCUMENT),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_DOCUMENT, q=q),
            "clear_view_url": reverse("ui:documents_list"),
        },
    )

@login_required
def documents_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert strategy: update the first matching (org, title) doc if found, else create.
    Note: titles are not unique; this is intentionally simple for MVP.
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"title", "body", "template"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: title,body,template (optional: folder)")
            else:
                for idx, row in enumerate(reader, start=2):
                    try:
                        title = (row.get("title") or "").strip()
                        body = (row.get("body") or "").strip()
                        tmpl_name = (row.get("template") or "").strip()
                        folder_raw = (row.get("folder") or "").strip()
                        if not title:
                            errors.append(f"Line {idx}: missing title")
                            continue

                        tmpl = None
                        if tmpl_name:
                            tmpl = DocumentTemplate.objects.filter(organization=org, name=tmpl_name).first()
                            if not tmpl:
                                tmpl = DocumentTemplate.objects.create(organization=org, name=tmpl_name, body="")
                                errors.append(f"Line {idx}: created missing template '{tmpl_name}'")

                        folder_obj = None
                        if folder_raw:
                            # Support "Parent/Child" style paths.
                            parts = [p.strip() for p in folder_raw.replace("\\\\", "/").split("/") if p.strip()]
                            parent = None
                            for part in parts:
                                parent, _ = DocumentFolder.objects.get_or_create(
                                    organization=org,
                                    parent=parent,
                                    name=part,
                                )
                            folder_obj = parent

                        obj = Document.objects.filter(organization=org, title=title).order_by("id").first()
                        if not obj:
                            Document.objects.create(
                                organization=org,
                                title=title,
                                body=body,
                                template=tmpl,
                                folder=folder_obj,
                                created_by=request.user,
                            )
                            created += 1
                        else:
                            changed = False
                            if obj.body != body:
                                obj.body = body
                                changed = True
                            if (obj.template_id or None) != (tmpl.id if tmpl else None):
                                obj.template = tmpl
                                changed = True
                            if (obj.folder_id or None) != (folder_obj.id if folder_obj else None):
                                obj.folder = folder_obj
                                changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/documents_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Docs", reverse("ui:documents_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/documents_import.html",
        {"org": org, "crumbs": _crumbs(("Docs", reverse("ui:documents_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )

@login_required
def documents_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_DOCUMENT, q=q)
    qs = Document.objects.select_related("template", "folder").filter(organization=org).order_by("-updated_at")
    qs = _filter_archived_qs(request, qs)
    if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_docs_q(request.user, org)).distinct()
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(body__icontains=q))
    rows = []
    for d in qs[:5000]:
        rows.append(
            [
                d.title or "",
                d.folder.name if d.folder_id else "",
                d.updated_at.isoformat() if d.updated_at else "",
                d.template.name if d.template_id else "",
            ]
        )
    return _csv_http_response(
        filename=f"{org.name}-docs.csv",
        header=["title", "folder", "updated_at", "template"],
        rows=rows,
    )

@login_required
@require_POST
def documents_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    ids = [int(x) for x in request.POST.getlist("ids") if (x or "").isdigit()]
    action = (request.POST.get("action") or "").strip()
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)

    if action == "move_folder":
        if not ids:
            return _redirect_back(request, fallback_url=reverse("ui:documents_list"))

        folder_raw = (request.POST.get("folder_id") or "").strip()
        folder_id = int(folder_raw) if folder_raw.isdigit() else None
        if folder_id == 0:
            folder_id = None
        folder_obj = None
        if folder_id:
            folder_obj = DocumentFolder.objects.filter(organization=org, archived_at__isnull=True, id=folder_id).first()
            if not folder_obj:
                return _redirect_back(request, fallback_url=reverse("ui:documents_list"))

        qs = Document.objects.filter(organization=org, id__in=ids)
        if not can_admin:
            qs = qs.filter(_visible_docs_q(request.user, org)).distinct()
        for d in list(qs):
            d.folder = folder_obj
            d.save(update_fields=["folder", "updated_at"])
        return _redirect_back(request, fallback_url=reverse("ui:documents_list"))

    # Default bulk actions (archive/tag) as before.
    return _bulk_action(
        request,
        org=org,
        model_cls=Document,
        base_qs=Document.objects.filter(organization=org),
        list_url_name="ui:documents_list",
        supports_tags=True,
    )


@login_required
def documents_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = DocumentForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.created_by = request.user
            obj.save()
            form.save_m2m()
            if obj.visibility != Document.VIS_SHARED:
                obj.allowed_users.clear()
            return redirect("ui:document_detail", document_id=obj.id)
    else:
        init = {}
        title = (request.GET.get("title") or "").strip()
        if title:
            init["title"] = title
        folder = (request.GET.get("folder") or "").strip()
        if folder.isdigit():
            init["folder"] = int(folder)
        form = DocumentForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Docs", reverse("ui:documents_list")), ("New", None)), "title": "New document", "form": form},
    )


@login_required
def document_folders_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)

    qs = DocumentFolder.objects.filter(organization=org).order_by("parent_id", "name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q))
    folders = list(qs[:5000])
    return render(
        request,
        "ui/document_folders_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Docs", reverse("ui:documents_list")), ("Folders", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "folders": folders,
            "new_url": reverse("ui:document_folder_new"),
            "bulk_url": reverse("ui:document_folders_bulk"),
        },
    )


@login_required
def document_folder_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = DocumentFolderForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:document_folder_detail", folder_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        parent = (request.GET.get("parent") or "").strip()
        if parent.isdigit():
            init["parent"] = int(parent)
        form = DocumentFolderForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Docs", reverse("ui:documents_list")), ("Folders", reverse("ui:document_folders_list")), ("New", None)), "title": "New document folder", "form": form},
    )


@login_required
def document_folder_detail(request: HttpRequest, folder_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    folder = get_object_or_404(DocumentFolder.objects.select_related("parent"), organization=org, id=folder_id)

    if request.method == "POST":
        form = DocumentFolderForm(request.POST, instance=folder, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:document_folder_detail", folder_id=folder.id)
    else:
        form = DocumentFolderForm(instance=folder, org=org)

    dqs = Document.objects.filter(organization=org, folder=folder, archived_at__isnull=True).select_related("template").order_by("-updated_at")
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        dqs = dqs.filter(_visible_docs_q(request.user, org)).distinct()
    documents = list(dqs[:200])

    folder_chain = _doc_folder_crumb_items(folder=folder)
    # Don't duplicate current folder in crumbs (folder_chain already includes it).
    crumbs = _crumbs(("Docs", reverse("ui:documents_list")), ("Folders", reverse("ui:document_folders_list")), *folder_chain)

    return render(
        request,
        "ui/document_folder_detail.html",
        {
            "org": org,
            "crumbs": crumbs,
            "folder": folder,
            "form": form,
            "can_admin": can_admin,
            "documents": documents,
        },
    )


@login_required
def document_folder_delete(request: HttpRequest, folder_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    folder = get_object_or_404(DocumentFolder, organization=org, id=folder_id)
    cancel = reverse("ui:document_folder_detail", kwargs={"folder_id": folder.id})
    redirect_url = reverse("ui:document_folders_list")

    def _go():
        if folder.archived_at is None:
            folder.archived_at = timezone.now()
            folder.save(update_fields=["archived_at"])

    warning = "Docs remain and will keep their folder reference unless you move them. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="document folder",
        label=str(folder),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
@require_POST
def document_folders_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=DocumentFolder,
        base_qs=DocumentFolder.objects.filter(organization=org),
        list_url_name="ui:document_folders_list",
        supports_tags=False,
    )


@login_required
def document_detail(request: HttpRequest, document_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    qs = Document.objects.select_related("template", "folder").filter(organization=org)
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_docs_q(request.user, org)).distinct()
    doc = get_object_or_404(qs, id=document_id)

    if request.method == "POST" and request.POST.get("_action") == "toggle_flag":
        if not _can_view_document(user=request.user, org=org, doc=doc):
            raise PermissionDenied("Not allowed.")
        if doc.flagged_at is None:
            doc.flagged_at = timezone.now()
            doc.flagged_by = request.user
        else:
            doc.flagged_at = None
            doc.flagged_by = None
        doc.save(update_fields=["flagged_at", "flagged_by"])
        return redirect("ui:document_detail", document_id=doc.id)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=doc, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:document_detail", document_id=doc.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=doc)
        return redirect(request.get_full_path())

    if request.method == "POST" and request.POST.get("_action") == "set_review_state":
        next_state = (request.POST.get("review_state") or "").strip()
        allowed_states = {Document.REVIEW_DRAFT, Document.REVIEW_IN_REVIEW, Document.REVIEW_APPROVED}
        if next_state in allowed_states:
            if next_state == Document.REVIEW_APPROVED and not _is_org_admin(request.user, org):
                raise PermissionDenied("Org admin role required to approve documents.")
            old_state = doc.review_state
            if old_state != next_state:
                doc.review_state = next_state
                if next_state == Document.REVIEW_DRAFT:
                    doc.reviewed_by = None
                    doc.reviewed_at = None
                else:
                    doc.reviewed_by = request.user
                    doc.reviewed_at = timezone.now()
                doc.save(update_fields=["review_state", "reviewed_by", "reviewed_at", "updated_at"])
                _audit_event(
                    request=request,
                    org=org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="docsapp.DocumentReview",
                    object_pk=str(doc.id),
                    summary=f"Review state changed: {_doc_review_label(old_state)} -> {_doc_review_label(next_state)}.",
                )
        return redirect("ui:document_detail", document_id=doc.id)

    if request.method == "POST" and request.POST.get("_action") == "add_comment":
        comment_form = DocumentCommentForm(request.POST, org=org)
        if comment_form.is_valid():
            comment = comment_form.save(commit=False)
            comment.organization = org
            comment.document = doc
            comment.created_by = request.user
            comment.save()
            _create_doc_mention_notifications(org=org, doc=doc, comment=comment, actor=request.user)
            _audit_event(
                request=request,
                org=org,
                action=AuditEvent.ACTION_CREATE,
                model="docsapp.DocumentComment",
                object_pk=str(comment.id),
                summary=f"Comment added on document '{doc.title}'.",
            )
        return redirect("ui:document_detail", document_id=doc.id)

    if request.method == "POST" and request.POST.get("_action") == "delete_comment":
        try:
            comment_id = int(request.POST.get("comment_id") or "0")
        except Exception:
            comment_id = 0
        comment = get_object_or_404(DocumentComment, organization=org, document=doc, id=comment_id)
        if not (_is_org_admin(request.user, org) or (comment.created_by_id and int(comment.created_by_id) == int(request.user.id))):
            raise PermissionDenied("Not allowed.")
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_DELETE,
            model="docsapp.DocumentComment",
            object_pk=str(comment.id),
            summary=f"Comment deleted from document '{doc.title}'.",
        )
        comment.delete()
        return redirect("ui:document_detail", document_id=doc.id)

    if request.method == "POST":
        form = DocumentForm(request.POST, instance=doc, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:document_detail", document_id=doc.id)
    else:
        form = DocumentForm(instance=doc, org=org)
    relationships = _relationships_for_object(org=org, obj=doc, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    edit_mode = _is_edit_mode(request)
    crumbs = None
    if doc.folder_id:
        folder_items = _doc_folder_crumb_items(folder=doc.folder)
        crumbs = _crumbs(("Docs", reverse("ui:documents_list")), ("Folders", reverse("ui:document_folders_list")), *folder_items, (doc.title, None))
    else:
        crumbs = _crumbs(("Docs", reverse("ui:documents_list")), (doc.title, None))

    return render(
        request,
        "ui/document_detail.html",
        {
            "org": org,
            "crumbs": crumbs,
            "document": doc,
            "folder_label": (doc.folder.name if doc.folder_id else None),
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:document_detail", kwargs={"document_id": doc.id}) + "?edit=1",
            "view_url": reverse("ui:document_detail", kwargs={"document_id": doc.id}),
            "can_admin": can_admin,
            "attachments": _attachments_for_object(org=org, obj=doc),
            "notes": _notes_for_object(org=org, obj=doc),
            "comment_form": DocumentCommentForm(org=org),
            "comments": _doc_comments_for_document(org=org, doc=doc, limit=200),
            "note_ref": _ref_for_obj(doc),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=Document),
            "custom_values": _custom_field_values_for_object(org=org, obj=doc),
            "activity": _activity_for_object(org=org, model_cls=Document, obj_id=doc.id),
            "versions": _versions_for_object(org=org, obj=doc, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(doc)}",
            "review_state_label": _doc_review_label(doc.review_state),
        },
    )


@login_required
def document_delete(request: HttpRequest, document_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    doc = get_object_or_404(Document, id=document_id, organization=org)
    cancel = reverse("ui:document_detail", kwargs={"document_id": doc.id})
    redirect_url = reverse("ui:documents_list")

    def _go():
        if doc.archived_at is None:
            doc.archived_at = timezone.now()
            doc.save(update_fields=["archived_at"])

    return _confirm_delete(
        request,
        org=org,
        kind="document",
        label=str(doc),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )

@login_required
def templates_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_TEMPLATE, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = DocumentTemplate.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(body__icontains=q))
    templates = list(qs[:200])
    return render(
        request,
        "ui/templates_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Templates", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "templates": templates,
            "templates_new_url": reverse("ui:templates_new"),
            "export_url": reverse("ui:templates_export") + _qs_suffix(request),
            "import_url": reverse("ui:templates_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=DocumentTemplate, ids=[t.id for t in templates]),
            "ref_prefix": _ref_prefix_for_model(DocumentTemplate),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_TEMPLATE),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_TEMPLATE, q=q),
            "clear_view_url": reverse("ui:templates_list"),
        },
    )

@login_required
def templates_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert by (org, name).
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"name", "body"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: name,body")
            else:
                for idx, row in enumerate(reader, start=2):
                    try:
                        name = (row.get("name") or "").strip()
                        body = (row.get("body") or "").strip()
                        if not name:
                            errors.append(f"Line {idx}: missing name")
                            continue

                        obj, was_created = DocumentTemplate.objects.get_or_create(
                            organization=org,
                            name=name,
                            defaults={"body": body},
                        )
                        if was_created:
                            created += 1
                        else:
                            if obj.body != body:
                                obj.body = body
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/templates_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Templates", reverse("ui:templates_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/templates_import.html",
        {"org": org, "crumbs": _crumbs(("Templates", reverse("ui:templates_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )

@login_required
def templates_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_TEMPLATE, q=q)
    qs = DocumentTemplate.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(body__icontains=q))
    rows = []
    for t in qs[:5000]:
        rows.append([t.name or "", t.created_at.isoformat() if t.created_at else ""])
    return _csv_http_response(
        filename=f"{org.name}-templates.csv",
        header=["name", "created_at"],
        rows=rows,
    )

@login_required
@require_POST
def templates_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=DocumentTemplate,
        base_qs=DocumentTemplate.objects.filter(organization=org),
        list_url_name="ui:templates_list",
        supports_tags=True,
    )


@login_required
def relationship_types_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    qs = RelationshipType.objects.filter(organization=org).order_by("name")
    can_manage = _is_org_admin(request.user, org)
    return render(
        request,
        "ui/relationship_types_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Relationship Types", None)),
            "types": qs,
            "can_manage": can_manage,
            "relationship_types_new_url": reverse("ui:relationship_types_new") if can_manage else None,
        },
    )


@login_required
def relationship_types_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    if request.method == "POST":
        form = RelationshipTypeForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:relationship_types_list")
    else:
        form = RelationshipTypeForm(org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Relationship Types", reverse("ui:relationship_types_list")), ("New", None)), "title": "New relationship type", "form": form},
    )


@login_required
def relationship_type_delete(request: HttpRequest, reltype_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    rt = get_object_or_404(RelationshipType, id=reltype_id, organization=org)
    cancel = reverse("ui:relationship_types_list")
    redirect_url = cancel

    def _go():
        rt.delete()  # cascades relationships

    warning = "All relationships using this type will be deleted."
    return _confirm_delete(
        request,
        org=org,
        kind="relationship type",
        label=str(rt),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )

@login_required
def tags_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    qs = Tag.objects.select_related("organization").filter(Q(organization__isnull=True) | Q(organization=org)).order_by("name")
    if q:
        qs = qs.filter(Q(name__icontains=q))
    return render(
        request,
        "ui/tags_list.html",
        {"org": org, "crumbs": _crumbs(("Tags", None)), "q": q, "tags": qs, "tags_new_url": reverse("ui:tags_new")},
    )


@login_required
def tags_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    is_superuser = bool(getattr(request.user, "is_superuser", False))
    if request.method == "POST":
        form = TagForm(request.POST, org=org, is_superuser=is_superuser)
        if form.is_valid():
            obj = form.save()
            return redirect("ui:tag_detail", tag_id=obj.id)
    else:
        form = TagForm(org=org, is_superuser=is_superuser)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Tags", reverse("ui:tags_list")), ("New", None)), "title": "New tag", "form": form},
    )


@login_required
def tag_detail(request: HttpRequest, tag_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    qs = Tag.objects.select_related("organization").filter(Q(organization__isnull=True) | Q(organization=org))
    tag = get_object_or_404(qs, id=tag_id)
    is_superuser = bool(getattr(request.user, "is_superuser", False))
    can_edit = bool(is_superuser or tag.organization_id is not None)
    if request.method == "POST":
        if not can_edit:
            raise PermissionDenied("Only superusers can modify global tags.")
        form = TagForm(request.POST, instance=tag, org=org, is_superuser=is_superuser)
        if form.is_valid():
            form.save()
            return redirect("ui:tag_detail", tag_id=tag.id)
    else:
        init = {}
        if is_superuser:
            init["global_tag"] = tag.organization_id is None
        form = TagForm(instance=tag, initial=init, org=org, is_superuser=is_superuser)
        if not can_edit:
            for f in form.fields.values():
                f.disabled = True
    return render(
        request,
        "ui/tag_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Tags", reverse("ui:tags_list")), (tag.name, None)),
            "tag": tag,
            "form": form,
            "can_edit": can_edit,
        },
    )


@login_required
def tag_delete(request: HttpRequest, tag_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    qs = Tag.objects.select_related("organization").filter(Q(organization__isnull=True) | Q(organization=org))
    tag = get_object_or_404(qs, id=tag_id)
    is_superuser = bool(getattr(request.user, "is_superuser", False))
    if tag.organization_id is None and not is_superuser:
        raise PermissionDenied("Only superusers can delete global tags.")
    cancel = reverse("ui:tag_detail", kwargs={"tag_id": tag.id})
    redirect_url = reverse("ui:tags_list")

    def _go():
        tag.delete()

    return _confirm_delete(
        request,
        org=org,
        kind="tag",
        label=str(tag),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        on_confirm=_go,
    )

def _ui_object_url(app_label: str, model: str, obj_id: str) -> str | None:
    """
    Best-effort mapping from ContentType refs to UI URLs.
    """

    model = (model or "").lower()
    app_label = (app_label or "").lower()
    try:
        obj_id_int = int(str(obj_id))
    except Exception:
        return None

    if app_label == "assets" and model == "asset":
        return reverse("ui:asset_detail", kwargs={"asset_id": obj_id_int})
    if app_label == "assets" and model == "configurationitem":
        return reverse("ui:config_item_detail", kwargs={"item_id": obj_id_int})
    if app_label == "docsapp" and model == "document":
        return reverse("ui:document_detail", kwargs={"document_id": obj_id_int})
    if app_label == "docsapp" and model == "documenttemplate":
        return reverse("ui:template_detail", kwargs={"template_id": obj_id_int})
    if app_label == "secretsapp" and model == "passwordentry":
        return reverse("ui:password_detail", kwargs={"password_id": obj_id_int})
    if app_label == "secretsapp" and model == "passwordfolder":
        return reverse("ui:password_folder_detail", kwargs={"folder_id": obj_id_int})
    if app_label == "people" and model == "contact":
        return reverse("ui:contact_detail", kwargs={"contact_id": obj_id_int})
    if app_label == "core" and model == "location":
        return reverse("ui:location_detail", kwargs={"location_id": obj_id_int})
    if app_label == "netapp" and model == "domain":
        return reverse("ui:domain_detail", kwargs={"domain_id": obj_id_int})
    if app_label == "netapp" and model == "sslcertificate":
        return reverse("ui:sslcert_detail", kwargs={"sslcert_id": obj_id_int})
    if app_label == "checklists" and model == "checklist":
        return reverse("ui:checklist_detail", kwargs={"checklist_id": obj_id_int})
    if app_label == "checklists" and model == "checklistrun":
        return reverse("ui:checklist_run_detail", kwargs={"run_id": obj_id_int})
    if app_label == "flexassets" and model == "flexibleasset":
        try:
            fa = FlexibleAsset.objects.select_related("asset_type").filter(id=obj_id_int).first()
            if not fa:
                return None
            return reverse("ui:flex_asset_detail", kwargs={"type_id": fa.asset_type_id, "asset_id": fa.id})
        except Exception:
            return None
    if app_label == "flexassets" and model == "flexibleassettype":
        return reverse("ui:flex_type_detail", kwargs={"type_id": obj_id_int})
    return None


@login_required
def relationship_detail(request: HttpRequest, relationship_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    rel = get_object_or_404(
        Relationship.objects.filter(organization=org).select_related(
            "relationship_type", "source_content_type", "target_content_type", "created_by"
        ),
        id=relationship_id,
    )

    if request.method == "POST":
        rel.notes = (request.POST.get("notes") or "").strip()
        rel.save(update_fields=["notes"])
        return redirect("ui:relationship_detail", relationship_id=rel.id)

    view_row = (_relationships_view(request=request, org=org, relationships=[rel]) or [{}])[0]

    src = {
        "ref": f"{rel.source_content_type.app_label}.{rel.source_content_type.model}:{rel.source_object_id}",
        "label": (view_row.get("source") or {}).get("label") or rel.source_label(),
        "url": (view_row.get("source") or {}).get("url"),
    }
    tgt = {
        "ref": f"{rel.target_content_type.app_label}.{rel.target_content_type.model}:{rel.target_object_id}",
        "label": (view_row.get("target") or {}).get("label") or rel.target_label(),
        "url": (view_row.get("target") or {}).get("url"),
    }

    return render(
        request,
        "ui/relationship_detail.html",
        {"org": org, "crumbs": _crumbs(("Relationships", reverse("ui:relationships_list")), (f"#{rel.id}", None)), "rel": rel, "src": src, "tgt": tgt},
    )


@login_required
def attachment_delete(request: HttpRequest, attachment_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    a = get_object_or_404(Attachment.objects.select_related("content_type"), id=attachment_id, organization=org)

    obj_url = None
    if a.content_type_id and a.object_id:
        obj_url = _ui_object_url(a.content_type.app_label, a.content_type.model, a.object_id)

    cancel_url = obj_url or reverse("ui:dashboard")
    redirect_url = cancel_url

    def _go():
        a.delete()

    warning = "This removes the attachment record and deletes the underlying file."
    return _confirm_delete(
        request,
        org=org,
        kind="attachment",
        label=a.filename or f"Attachment #{a.id}",
        cancel_url=cancel_url,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


@login_required
def file_folders_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)

    qs = FileFolder.objects.filter(organization=org).select_related("parent").order_by("parent_id", "name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q))
    folders = list(qs[:5000])
    return render(
        request,
        "ui/file_folders_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Files", reverse("ui:files_list")), ("Folders", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "folders": folders,
            "new_url": reverse("ui:file_folder_new"),
            "bulk_url": reverse("ui:file_folders_bulk"),
        },
    )


@login_required
def file_folder_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = FileFolderForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:file_folder_detail", folder_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        parent = (request.GET.get("parent") or "").strip()
        if parent.isdigit():
            init["parent"] = int(parent)
        form = FileFolderForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("Files", reverse("ui:files_list")), ("Folders", reverse("ui:file_folders_list")), ("New", None)),
            "title": "New file folder",
            "form": form,
        },
    )


@login_required
def file_folder_detail(request: HttpRequest, folder_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    folder = get_object_or_404(FileFolder.objects.select_related("parent"), organization=org, id=folder_id)

    if request.method == "POST":
        form = FileFolderForm(request.POST, instance=folder, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:file_folder_detail", folder_id=folder.id)
    else:
        form = FileFolderForm(instance=folder, org=org)

    # Visible attachments in this folder.
    aqs = _attachments_queryset_visible_to_user(request=request, org=org).select_related("folder").prefetch_related("tags")
    aqs = aqs.filter(folder=folder).order_by("-created_at")
    items = list(aqs[:50])

    return render(
        request,
        "ui/file_folder_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Files", reverse("ui:files_list")), ("Folders", reverse("ui:file_folders_list")), (folder.name, None)),
            "folder": folder,
            "form": form,
            "can_admin": can_admin,
            "items": items,
            "files_in_folder_url": reverse("ui:files_list") + "?" + urlencode({"folder": str(folder.id)}),
        },
    )


@login_required
def file_folder_delete(request: HttpRequest, folder_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    folder = get_object_or_404(FileFolder, organization=org, id=folder_id)
    cancel = reverse("ui:file_folder_detail", kwargs={"folder_id": folder.id})
    redirect_url = reverse("ui:file_folders_list")

    def _go():
        if folder.archived_at is None:
            folder.archived_at = timezone.now()
            folder.save(update_fields=["archived_at"])

    warning = "Files in this folder will remain and can be re-filed. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="file folder",
        label=str(folder),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived folders are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
@require_POST
def file_folders_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=FileFolder,
        base_qs=FileFolder.objects.filter(organization=org),
        list_url_name="ui:file_folders_list",
        supports_tags=False,
    )


@login_required
@require_POST
def files_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization

    ids = [int(x) for x in request.POST.getlist("ids") if (x or "").isdigit()]
    action = (request.POST.get("action") or "").strip()
    if not ids:
        return _redirect_back(request, fallback_url=reverse("ui:files_list"))

    qs = _attachments_queryset_visible_to_user(request=request, org=org).filter(id__in=ids)

    if action == "tag_add":
        tag_id = request.POST.get("tag_id")
        tag_id = int(tag_id) if (tag_id or "").isdigit() else None
        if not tag_id:
            return _redirect_back(request, fallback_url=reverse("ui:files_list"))
        tag = _tags_available_for_org(org).filter(id=tag_id).first()
        if not tag:
            return _redirect_back(request, fallback_url=reverse("ui:files_list"))
        for a in list(qs):
            try:
                a.tags.add(tag)
            except Exception:
                continue
        return _redirect_back(request, fallback_url=reverse("ui:files_list"))

    if action == "move_folder":
        folder_raw = (request.POST.get("folder_id") or "").strip()
        if folder_raw == "__keep__":
            return _redirect_back(request, fallback_url=reverse("ui:files_list"))
        folder_id = int(folder_raw) if folder_raw.isdigit() else None
        folder = FileFolder.objects.filter(organization=org, archived_at__isnull=True, id=folder_id).first() if folder_id else None
        qs.update(folder=folder)
        return _redirect_back(request, fallback_url=reverse("ui:files_list"))

    if action == "delete":
        _require_org_admin(request.user, org)
        if not _is_reauthed(request):
            nxt = (request.POST.get("next") or "").strip() or reverse("ui:files_list")
            return redirect(reverse("ui:reauth") + "?" + urlencode({"next": nxt}))
        for a in list(qs.select_related("content_type")):
            try:
                a.delete()
            except Exception:
                continue
        return _redirect_back(request, fallback_url=reverse("ui:files_list"))

    return _redirect_back(request, fallback_url=reverse("ui:files_list"))


@login_required
def files_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)
    params, active_view = _apply_saved_view_params(
        request=request,
        org=org,
        model_key=SavedView.KEY_FILE,
        params={
            "q": (request.GET.get("q") or "").strip(),
            "ref": (request.GET.get("ref") or "").strip(),
            "folder": (request.GET.get("folder") or "").strip(),
            "tag": (request.GET.get("tag") or "").strip(),
            "attached": (request.GET.get("attached") or "").strip(),
            "has_versions": (request.GET.get("has_versions") or "").strip(),
            "has_shares": (request.GET.get("has_shares") or "").strip(),
            "sort": (request.GET.get("sort") or "").strip(),
        },
    )
    q = (params.get("q") or "").strip()
    ref = (params.get("ref") or "").strip()
    folder_raw = (params.get("folder") or "").strip()
    folder_id = int(folder_raw) if folder_raw.isdigit() else None
    tag_raw = (params.get("tag") or "").strip()
    tag_id = int(tag_raw) if tag_raw.isdigit() else None
    attached_scope = (params.get("attached") or "").strip().lower()
    if attached_scope not in {"", "org", "object"}:
        attached_scope = ""
    has_versions = (params.get("has_versions") or "").strip() == "1"
    has_shares = (params.get("has_shares") or "").strip() == "1"
    sort = (params.get("sort") or "").strip().lower()
    if sort not in {"", "newest", "oldest", "name_asc", "name_desc", "size_desc", "size_asc"}:
        sort = "newest"
    if not sort:
        sort = "newest"
    filter_invalid = False
    filter_label = None

    if request.method == "POST" and request.POST.get("_action") == "upload":
        f = request.FILES.get("file")
        if f:
            folder_raw2 = (request.POST.get("folder_id") or "").strip()
            folder2_id = int(folder_raw2) if folder_raw2.isdigit() else None
            folder = FileFolder.objects.filter(organization=org, archived_at__isnull=True, id=folder2_id).first() if folder2_id else None
            a = Attachment.objects.create(
                organization=org,
                uploaded_by=request.user,
                file=f,
                filename=getattr(f, "name", "") or "",
                folder=folder,
            )
            # Tags (optional)
            tids = [int(x) for x in request.POST.getlist("tag_ids") if (x or "").isdigit()]
            if tids:
                for t in _tags_available_for_org(org).filter(id__in=tids):
                    try:
                        a.tags.add(t)
                    except Exception:
                        continue
        return redirect("ui:files_list")

    qs = _attachments_queryset_visible_to_user(request=request, org=org)
    qs = qs.select_related("folder").prefetch_related("tags").annotate(
        version_count=Count("versions", distinct=True),
        share_count=Count("share_links", distinct=True),
    )

    if ref:
        parsed = _parse_ref(ref)
        if not parsed:
            filter_invalid = True
        else:
            ct, oid = parsed
            qs = qs.filter(content_type=ct, object_id=str(oid))
            try:
                obj = ct.model_class().objects.filter(organization=org, id=int(oid)).first()
                if obj:
                    filter_label = _human_ref_label(ct=ct, obj=obj)
                else:
                    filter_label = _human_ref_label(ct=ct, oid=oid)
            except Exception:
                filter_label = ref

    if q:
        qs = qs.filter(Q(filename__icontains=q) | Q(file__icontains=q) | Q(uploaded_by__username__icontains=q))
    if attached_scope == "org":
        qs = qs.filter(content_type__isnull=True)
    elif attached_scope == "object":
        qs = qs.filter(content_type__isnull=False, object_id__isnull=False)

    if folder_id:
        qs = qs.filter(folder_id=int(folder_id))
    if tag_id:
        qs = qs.filter(tags__id=int(tag_id)).distinct()
    if has_versions:
        qs = qs.filter(versions__isnull=False).distinct()
    if has_shares:
        qs = qs.filter(share_links__isnull=False).distinct()

    if sort == "oldest":
        qs = qs.order_by("created_at", "id")
    elif sort == "name_asc":
        qs = qs.order_by("filename", "id")
    elif sort == "name_desc":
        qs = qs.order_by("-filename", "-id")
    else:
        qs = qs.order_by("-created_at", "-id")

    items = []
    for a in list(qs[:200]):
        attached_label = None
        attached_url = None
        ct = getattr(a, "content_type", None)
        oid = getattr(a, "object_id", None)
        if ct and oid:
            attached_label = _human_ref_label(ct=ct, oid=oid)
            try:
                model_cls = ct.model_class()
                if model_cls is not None and hasattr(model_cls, "organization_id"):
                    obj = model_cls.objects.filter(organization=org, id=int(oid)).first()
                else:
                    obj = model_cls.objects.filter(id=int(oid)).first() if model_cls is not None else None
                if obj:
                    attached_label = _human_ref_label(ct=ct, obj=obj)
                    attached_url = _url_for_object_detail(obj)
            except Exception:
                pass

        size = None
        try:
            size = int(a.file.size) if a.file else None
        except Exception:
            size = None

        items.append(
            {
                "id": a.id,
                "filename": a.filename or (Path(getattr(a.file, "name", "")).name if a.file else f"Attachment {a.id}"),
                "created_at": a.created_at,
                "uploaded_by": getattr(a, "uploaded_by", None),
                "size": size,
                "folder": getattr(a, "folder", None),
                "tags": list(getattr(a, "tags", []).all()) if hasattr(a, "tags") else [],
                "detail_url": reverse("ui:file_detail", kwargs={"attachment_id": a.id}),
                "download_url": reverse("ui:file_download", kwargs={"attachment_id": a.id}),
                "attached_label": attached_label,
                "attached_url": attached_url,
                "has_versions": bool(getattr(a, "version_count", 0)),
                "has_shares": bool(getattr(a, "share_count", 0)),
            }
        )

    if sort == "size_desc":
        items.sort(key=lambda x: int(x.get("size") or 0), reverse=True)
    elif sort == "size_asc":
        items.sort(key=lambda x: int(x.get("size") or 0))

    folders = list(FileFolder.objects.filter(organization=org, archived_at__isnull=True).select_related("parent").order_by("parent_id", "name")[:5000])
    tags = list(_tags_available_for_org(org)[:500])

    return render(
        request,
        "ui/files_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Files", None)),
            "q": q,
            "items": items,
            "filter_ref": ref,
            "filter_label": filter_label,
            "filter_invalid": filter_invalid,
            "folders": folders,
            "folder_id": folder_id,
            "tags": tags,
            "tag_id": tag_id,
            "attached_scope": attached_scope,
            "has_versions": has_versions,
            "has_shares": has_shares,
            "sort": sort,
            "can_admin": can_admin,
            "bulk_url": reverse("ui:files_bulk"),
            "folders_url": reverse("ui:file_folders_list"),
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_FILE),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(
                request=request,
                model_key=SavedView.KEY_FILE,
                q=q,
                params={
                    "q": q,
                    "ref": ref,
                    "folder": str(folder_id) if folder_id else "",
                    "tag": str(tag_id) if tag_id else "",
                    "attached": attached_scope,
                    "has_versions": "1" if has_versions else "",
                    "has_shares": "1" if has_shares else "",
                    "sort": sort,
                },
            ),
            "clear_view_url": reverse("ui:files_list"),
        },
    )


@login_required
def backups_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    policy, _ = BackupPolicy.objects.get_or_create(organization=org)

    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip()
        if action == "create":
            snap = BackupSnapshot.objects.create(organization=org, created_by=request.user, status=BackupSnapshot.STATUS_PENDING)
            _audit_event(
                request=request,
                org=org,
                action=AuditEvent.ACTION_UPDATE,
                model="backups.BackupSnapshot",
                object_pk=str(snap.id),
                summary="Manual backup snapshot requested.",
            )
            return redirect("ui:backups_list")
        if action == "policy_save":
            enabled = (request.POST.get("enabled") or "").strip() == "1"
            try:
                interval_hours = int(request.POST.get("interval_hours") or 24)
            except Exception:
                interval_hours = 24
            if interval_hours <= 0:
                interval_hours = 24
            try:
                retention_count = int(request.POST.get("retention_count") or 30)
            except Exception:
                retention_count = 30
            if retention_count < 0:
                retention_count = 0

            policy.enabled = enabled
            policy.interval_hours = interval_hours
            policy.retention_count = retention_count

            # When enabling for the first time, schedule immediately.
            if policy.enabled and policy.next_run_at is None:
                policy.next_run_at = timezone.now()
            policy.save()
            _audit_event(
                request=request,
                org=org,
                action=AuditEvent.ACTION_UPDATE,
                model="backups.BackupPolicy",
                object_pk=str(policy.id),
                summary=f"Backup policy updated: enabled={int(enabled)}, interval_hours={interval_hours}, retention_count={retention_count}.",
            )
            return redirect("ui:backups_list")
        if action == "schedule_now":
            # Best-effort: enqueue a system snapshot immediately unless one is already pending/running.
            if not BackupSnapshot.objects.filter(
                organization=org, status__in=[BackupSnapshot.STATUS_PENDING, BackupSnapshot.STATUS_RUNNING]
            ).exists():
                snap = BackupSnapshot.objects.create(organization=org, created_by=None, status=BackupSnapshot.STATUS_PENDING)
                _audit_event(
                    request=request,
                    org=org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="backups.BackupSnapshot",
                    object_pk=str(snap.id),
                    summary="Backup scheduler run-now requested.",
                )
            return redirect("ui:backups_list")

    qs = BackupSnapshot.objects.filter(organization=org).order_by("-created_at")[:200]
    return render(
        request,
        "ui/backups_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Backups", None)),
            "items": list(qs),
            "create_url": reverse("ui:backups_list"),
            "policy": policy,
        },
    )


@login_required
def backup_download(request: HttpRequest, backup_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    b = get_object_or_404(BackupSnapshot.objects.select_related("created_by"), organization=org, id=backup_id)
    if b.status != BackupSnapshot.STATUS_SUCCESS or not b.file:
        raise PermissionDenied("Backup not ready.")
    try:
        f = b.file.open("rb")
    except Exception:
        raise PermissionDenied("Backup file unavailable.")
    _audit_event(
        request=request,
        org=org,
        action=AuditEvent.ACTION_UPDATE,
        model="backups.BackupSnapshot",
        object_pk=str(b.id),
        summary=f"Downloaded backup snapshot '{b.filename or b.id}'.",
    )
    filename = b.filename or Path(getattr(b.file, "name", "")).name or f"backup-{b.id}.zip"
    return FileResponse(f, as_attachment=True, filename=Path(filename).name, content_type="application/zip")


@login_required
def backup_delete(request: HttpRequest, backup_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    b = get_object_or_404(BackupSnapshot, organization=org, id=backup_id)
    cancel_url = reverse("ui:backups_list")
    redirect_url = reverse("ui:backups_list")

    def _go():
        bid = b.id
        label = b.filename or str(bid)
        b.delete()
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_DELETE,
            model="backups.BackupSnapshot",
            object_pk=str(bid),
            summary=f"Deleted backup snapshot '{label}'.",
        )

    warning = "This deletes the backup record and the underlying zip file from storage."
    return _confirm_delete(
        request,
        org=org,
        kind="backup",
        label=b.filename or f"Backup #{b.id}",
        cancel_url=cancel_url,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


def _validate_backup_restore_zip(*, file_obj) -> tuple[dict, dict, str | None]:
    """
    Validate a HomeGlue backup zip and return (manifest, derived, error).
    Does not read fixture.json fully into memory.
    """

    try:
        with zipfile.ZipFile(file_obj, "r") as z:
            names = set(z.namelist())
            if "manifest.json" not in names:
                return {}, {}, "manifest.json is missing."
            if "fixture.json" not in names:
                return {}, {}, "fixture.json is missing."

            try:
                manifest = json.loads(z.read("manifest.json").decode("utf-8"))
            except Exception:
                return {}, {}, "manifest.json is not valid JSON."

            try:
                fixture_info = z.getinfo("fixture.json")
                fixture_bytes = int(getattr(fixture_info, "file_size", 0) or 0)
            except Exception:
                fixture_bytes = 0

            media_files = 0
            media_bytes = 0
            for info in z.infolist():
                name = info.filename or ""
                if not name.startswith("media/"):
                    continue
                if name.endswith("/"):
                    continue
                media_files += 1
                try:
                    media_bytes += int(getattr(info, "file_size", 0) or 0)
                except Exception:
                    pass

            derived = {
                "fixture_bytes": fixture_bytes,
                "media_files": media_files,
                "media_bytes": media_bytes,
            }

            try:
                v = int(manifest.get("homeglue_backup_version") or 0)
                if v < 1:
                    return manifest, derived, "Unsupported or missing homeglue_backup_version."
            except Exception:
                return manifest, derived, "Unsupported or missing homeglue_backup_version."

            return manifest, derived, None
    except zipfile.BadZipFile:
        return {}, {}, "Not a valid zip file."
    except Exception as e:
        return {}, {}, str(e)


def _safe_extract_media_zip(*, z: zipfile.ZipFile, media_root: Path) -> int:
    """
    Extract zip members under `media/` into media_root, preventing path traversal.
    Returns number of files extracted.
    """

    extracted = 0
    media_root = media_root.resolve()
    for info in z.infolist():
        name = info.filename or ""
        if not name.startswith("media/"):
            continue
        if name.endswith("/"):
            continue

        rel = name[len("media/") :].lstrip("/").replace("\\", "/")
        if not rel or rel.startswith("../") or "/../" in rel:
            continue

        out_path = (media_root / rel).resolve()
        if not str(out_path).startswith(str(media_root) + "/") and out_path != media_root:
            continue

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with z.open(info, "r") as src, open(out_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 256)
                if not chunk:
                    break
                dst.write(chunk)
        extracted += 1
    return extracted


@login_required
def backup_restore_list(request: HttpRequest) -> HttpResponse:
    """
    Guided restore wizard:
    - Upload a backup zip.
    - Validate structure + show manifest.
    - Allow downloading manifest/fixture and extracting media/ into this instance.
    """

    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    error = None

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            error = "No file uploaded."
        else:
            h = hashlib.sha256()
            total = 0
            for chunk in f.chunks():
                h.update(chunk)
                total += len(chunk)
            try:
                f.seek(0)
            except Exception:
                pass

            bundle = BackupRestoreBundle.objects.create(
                organization=org,
                uploaded_by=request.user,
                filename=getattr(f, "name", "") or "",
                bytes=int(total or 0),
                sha256=h.hexdigest(),
                status=BackupRestoreBundle.STATUS_UPLOADED,
            )
            bundle.file.save(bundle.filename or "backup.zip", f, save=True)

            try:
                with bundle.file.open("rb") as fh:
                    manifest, derived, err = _validate_backup_restore_zip(file_obj=fh)
            except Exception as e:
                manifest, derived, err = {}, {}, str(e)

            if err:
                bundle.status = BackupRestoreBundle.STATUS_INVALID
                bundle.error = err
                bundle.manifest = {"_derived": derived, **(manifest or {})}
                _audit_event(
                    request=request,
                    org=org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="backups.BackupRestoreBundle",
                    object_pk=str(bundle.id),
                    summary=f"Uploaded restore bundle '{bundle.filename}' (invalid): {err}",
                )
            else:
                bundle.status = BackupRestoreBundle.STATUS_VALID
                bundle.error = ""
                bundle.manifest = {"_derived": derived, **(manifest or {})}
                _audit_event(
                    request=request,
                    org=org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="backups.BackupRestoreBundle",
                    object_pk=str(bundle.id),
                    summary=f"Uploaded restore bundle '{bundle.filename}' (valid).",
                )
            bundle.validated_at = timezone.now()
            bundle.save(update_fields=["status", "error", "manifest", "validated_at", "updated_at"])

            return redirect("ui:backup_restore_detail", bundle_id=bundle.id)

    bundles = list(BackupRestoreBundle.objects.filter(organization=org).order_by("-created_at")[:200])
    return render(
        request,
        "ui/backup_restore_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Backups", reverse("ui:backups_list")), ("Restore", None)),
            "bundles": bundles,
            "error": error,
        },
    )


@login_required
def backup_restore_detail(request: HttpRequest, bundle_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    b = get_object_or_404(BackupRestoreBundle, organization=org, id=bundle_id)
    derived = {}
    try:
        derived = (b.manifest or {}).get("_derived") or {}
    except Exception:
        derived = {}

    # Show a concrete, copy-paste-ready command for "fresh stack" restores.
    zip_path = ""
    try:
        zip_path = str(Path(b.file.path))
    except Exception:
        zip_path = ""

    cmd = None
    if zip_path:
        cmd = f"docker compose exec -T web python manage.py restore_backup_zip --zip {zip_path} --extract-media --loaddata --apply"
    else:
        cmd = f"docker compose exec -T web python manage.py restore_backup_zip --bundle-id {b.id} --extract-media --loaddata --apply"

    return render(
        request,
        "ui/backup_restore_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Backups", reverse("ui:backups_list")), ("Restore", reverse("ui:backup_restore_list")), (f"Bundle {b.id}", None)),
            "bundle": b,
            "manifest": b.manifest or {},
            "derived": derived,
            "cmd": cmd,
            "extract_url": reverse("ui:backup_restore_extract_media", kwargs={"bundle_id": b.id}),
            "manifest_url": reverse("ui:backup_restore_manifest_download", kwargs={"bundle_id": b.id}),
            "fixture_url": reverse("ui:backup_restore_fixture_download", kwargs={"bundle_id": b.id}),
            "delete_url": reverse("ui:backup_restore_delete", kwargs={"bundle_id": b.id}),
            "is_reauthed": _is_reauthed(request),
            "reauth_url": reverse("ui:reauth") + "?" + urlencode({"next": request.get_full_path()}),
        },
    )


@login_required
def backup_restore_manifest_download(request: HttpRequest, bundle_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    b = get_object_or_404(BackupRestoreBundle, organization=org, id=bundle_id)
    if not b.file:
        raise PermissionDenied("Bundle file unavailable.")
    with b.file.open("rb") as fh:
        with zipfile.ZipFile(fh, "r") as z:
            try:
                raw = z.read("manifest.json")
            except Exception:
                raise PermissionDenied("manifest.json not found in this bundle.")
    _audit_event(
        request=request,
        org=org,
        action=AuditEvent.ACTION_UPDATE,
        model="backups.BackupRestoreBundle",
        object_pk=str(b.id),
        summary=f"Downloaded restore manifest for bundle '{b.filename or b.id}'.",
    )
    resp = HttpResponse(raw, content_type="application/json; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="manifest-{b.id}.json"'
    return resp


@login_required
def backup_restore_fixture_download(request: HttpRequest, bundle_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    b = get_object_or_404(BackupRestoreBundle, organization=org, id=bundle_id)
    if not b.file:
        raise PermissionDenied("Bundle file unavailable.")
    with b.file.open("rb") as fh:
        with zipfile.ZipFile(fh, "r") as z:
            try:
                raw = z.read("fixture.json")
            except Exception:
                raise PermissionDenied("fixture.json not found in this bundle.")
    _audit_event(
        request=request,
        org=org,
        action=AuditEvent.ACTION_UPDATE,
        model="backups.BackupRestoreBundle",
        object_pk=str(b.id),
        summary=f"Downloaded restore fixture for bundle '{b.filename or b.id}'.",
    )
    resp = HttpResponse(raw, content_type="application/json; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="fixture-{b.id}.json"'
    return resp


@login_required
@require_POST
def backup_restore_extract_media(request: HttpRequest, bundle_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    if not _is_reauthed(request):
        nxt = reverse("ui:backup_restore_detail", kwargs={"bundle_id": bundle_id})
        return redirect(reverse("ui:reauth") + "?" + urlencode({"next": nxt}))

    b = get_object_or_404(BackupRestoreBundle, organization=org, id=bundle_id)
    if not b.file:
        raise PermissionDenied("Bundle file unavailable.")

    media_root = Path(getattr(settings, "MEDIA_ROOT", "/data/media"))
    extracted = 0
    with b.file.open("rb") as fh:
        with zipfile.ZipFile(fh, "r") as z:
            extracted = _safe_extract_media_zip(z=z, media_root=media_root)

    b.media_extracted_at = timezone.now()
    b.save(update_fields=["media_extracted_at", "updated_at"])
    _audit_event(
        request=request,
        org=org,
        action=AuditEvent.ACTION_UPDATE,
        model="backups.BackupRestoreBundle",
        object_pk=str(b.id),
        summary=f"Extracted media from restore bundle '{b.filename or b.id}' ({extracted} file(s)).",
    )
    return redirect(reverse("ui:backup_restore_detail", kwargs={"bundle_id": b.id}) + "?" + urlencode({"extracted": str(extracted)}))


@login_required
def backup_restore_delete(request: HttpRequest, bundle_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    b = get_object_or_404(BackupRestoreBundle, organization=org, id=bundle_id)
    cancel_url = reverse("ui:backup_restore_detail", kwargs={"bundle_id": b.id})
    redirect_url = reverse("ui:backup_restore_list")

    def _go():
        bid = b.id
        label = b.filename or str(bid)
        try:
            if b.file:
                b.file.delete(save=False)
        except Exception:
            pass
        b.delete()
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_DELETE,
            model="backups.BackupRestoreBundle",
            object_pk=str(bid),
            summary=f"Deleted restore bundle '{label}'.",
        )

    warning = "This deletes the uploaded restore bundle file from storage."
    return _confirm_delete(
        request,
        org=org,
        kind="restore bundle",
        label=b.filename or f"Bundle #{b.id}",
        cancel_url=cancel_url,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


@login_required
def file_detail(request: HttpRequest, attachment_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    a = get_object_or_404(
        Attachment.objects.select_related("uploaded_by", "content_type", "folder").prefetch_related("tags"),
        id=attachment_id,
        organization=org,
    )
    if not _can_view_attachment(request=request, org=org, a=a):
        raise PermissionDenied("Not allowed to view this file.")
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)
    is_reauthed = _is_reauthed(request)
    reauth_url = reverse("ui:reauth") + "?" + urlencode({"next": request.get_full_path()})
    sess_key_share = f"file_share_new_url_{org.id}_{a.id}"
    share_new_url = request.session.pop(sess_key_share, "")
    if share_new_url:
        request.session.modified = True

    if request.method == "POST" and request.POST.get("_action") == "share_create":
        if not can_admin:
            raise PermissionDenied("Only org admins can create share links.")
        if not is_reauthed:
            return redirect(reauth_url)
        try:
            hours = int(request.POST.get("expires_in_hours") or 24)
        except Exception:
            hours = 24
        hours = max(1, min(24 * 90, int(hours)))
        one_time = (request.POST.get("one_time") or "").strip() == "1"
        label = (request.POST.get("label") or "").strip()
        passphrase = (request.POST.get("passphrase") or "").strip()
        max_downloads = None
        max_raw = (request.POST.get("max_downloads") or "").strip()
        if max_raw:
            try:
                max_downloads = max(1, min(100000, int(max_raw)))
            except Exception:
                max_downloads = None

        expires_at = timezone.now() + timedelta(hours=hours)
        token = ""
        for _ in range(3):
            token = AttachmentShareLink.build_new_token()
            token_hash = AttachmentShareLink.hash_token(token)
            try:
                sl = AttachmentShareLink(
                    organization=org,
                    attachment=a,
                    created_by=request.user if request.user.is_authenticated else None,
                    label=label,
                    token_hash=token_hash,
                    token_prefix=(token[:12] if token else ""),
                    expires_at=expires_at,
                    one_time=one_time,
                    max_downloads=max_downloads,
                )
                if passphrase:
                    sl.set_passphrase(passphrase)
                sl.save()
                AuditEvent.objects.create(
                    organization=org,
                    user=request.user if request.user.is_authenticated else None,
                    action=AuditEvent.ACTION_UPDATE,
                    model=f"{Attachment._meta.app_label}.{Attachment.__name__}",
                    object_pk=str(a.id),
                    summary=(
                        f"Created file SafeShare link{f' ({label})' if label else ''}; expires in {hours}h"
                        f"{' (one-time)' if one_time else ''}"
                        f"{' (passphrase protected)' if passphrase else ''}"
                        f"{f' (max {max_downloads} downloads)' if max_downloads else ''}."
                    ),
                )
                break
            except IntegrityError:
                token = ""
                continue
        if not token:
            raise PermissionDenied("Unable to create share link (try again).")
        base_url = (get_base_url() or "").strip().rstrip("/")
        if not base_url:
            base_url = request.build_absolute_uri("/").rstrip("/")
        request.session[sess_key_share] = f"{base_url}{reverse('public:file_share', kwargs={'token': token})}"
        request.session.modified = True
        return redirect("ui:file_detail", attachment_id=a.id)

    if request.method == "POST" and request.POST.get("_action") == "share_revoke":
        if not can_admin:
            raise PermissionDenied("Only org admins can revoke share links.")
        if not is_reauthed:
            return redirect(reauth_url)
        sid = (request.POST.get("share_id") or "").strip()
        if sid.isdigit():
            sl = AttachmentShareLink.objects.filter(organization=org, attachment=a, id=int(sid)).first()
            if sl and not sl.revoked_at:
                sl.revoked_at = timezone.now()
                sl.save(update_fields=["revoked_at"])
                AuditEvent.objects.create(
                    organization=org,
                    user=request.user if request.user.is_authenticated else None,
                    action=AuditEvent.ACTION_UPDATE,
                    model=f"{Attachment._meta.app_label}.{Attachment.__name__}",
                    object_pk=str(a.id),
                    summary=f"Revoked file SafeShare link #{sl.id}.",
                )
        return redirect("ui:file_detail", attachment_id=a.id)

    if request.method == "POST" and request.POST.get("_action") == "share_revoke_all":
        if not can_admin:
            raise PermissionDenied("Only org admins can revoke share links.")
        if not is_reauthed:
            return redirect(reauth_url)
        now = timezone.now()
        changed = AttachmentShareLink.objects.filter(organization=org, attachment=a, revoked_at__isnull=True).update(revoked_at=now)
        if changed:
            AuditEvent.objects.create(
                organization=org,
                user=request.user if request.user.is_authenticated else None,
                action=AuditEvent.ACTION_UPDATE,
                model=f"{Attachment._meta.app_label}.{Attachment.__name__}",
                object_pk=str(a.id),
                summary=f"Revoked all file SafeShare links ({changed}).",
            )
        return redirect("ui:file_detail", attachment_id=a.id)

    if request.method == "POST" and request.POST.get("_action") == "share_delete":
        if not can_admin:
            raise PermissionDenied("Only org admins can delete share links.")
        if not is_reauthed:
            return redirect(reauth_url)
        sid = (request.POST.get("share_id") or "").strip()
        if sid.isdigit():
            sl = AttachmentShareLink.objects.filter(organization=org, attachment=a, id=int(sid)).first()
            if sl and not sl.is_active():
                share_id = sl.id
                sl.delete()
                AuditEvent.objects.create(
                    organization=org,
                    user=request.user if request.user.is_authenticated else None,
                    action=AuditEvent.ACTION_UPDATE,
                    model=f"{Attachment._meta.app_label}.{Attachment.__name__}",
                    object_pk=str(a.id),
                    summary=f"Deleted inactive file SafeShare link #{share_id}.",
                )
        return redirect("ui:file_detail", attachment_id=a.id)

    if request.method == "POST" and request.POST.get("_action") == "upload_version":
        if not can_admin:
            raise PermissionDenied("Not allowed.")
        if not is_reauthed:
            return redirect(reauth_url)
        fnew = request.FILES.get("file")
        if fnew and a.file:
            # Capture current file as a version without copying bytes; ownership transfers to the version record.
            v = AttachmentVersion(attachment=a, uploaded_by=request.user, filename=a.filename or "")
            v.file.name = getattr(a.file, "name", "") or ""
            try:
                v.bytes = int(a.file.size)
            except Exception:
                v.bytes = None
            v.save()

            a.file = fnew
            a.filename = getattr(fnew, "name", "") or a.filename
            a.uploaded_by = request.user
            a.save()
        return redirect("ui:file_detail", attachment_id=a.id)

    if request.method == "POST" and request.POST.get("_action") == "save_meta":
        folder_raw = (request.POST.get("folder_id") or "").strip()
        folder_id = int(folder_raw) if folder_raw.isdigit() else None
        folder = FileFolder.objects.filter(organization=org, archived_at__isnull=True, id=folder_id).first() if folder_id else None
        a.folder = folder
        a.save(update_fields=["folder"])
        # Replace tags
        tids = [int(x) for x in request.POST.getlist("tag_ids") if (x or "").isdigit()]
        a.tags.clear()
        if tids:
            for t in _tags_available_for_org(org).filter(id__in=tids):
                try:
                    a.tags.add(t)
                except Exception:
                    continue
        return redirect("ui:file_detail", attachment_id=a.id)

    attached_label = None
    attached_url = None
    ct = getattr(a, "content_type", None)
    oid = getattr(a, "object_id", None)
    if ct and oid:
        attached_label = _human_ref_label(ct=ct, oid=oid)
        try:
            model_cls = ct.model_class()
            if model_cls is Document:
                obj = Document.objects.filter(organization=org, id=int(oid)).first()
                if obj and _can_view_document(user=request.user, org=org, doc=obj):
                    attached_label = _human_ref_label(ct=ct, obj=obj)
                    attached_url = _url_for_object_detail(obj)
            elif model_cls is PasswordEntry:
                obj = PasswordEntry.objects.filter(organization=org, id=int(oid)).first()
                if obj and _can_view_password(user=request.user, org=org, entry=obj):
                    attached_label = _human_ref_label(ct=ct, obj=obj)
                    attached_url = _url_for_object_detail(obj)
            else:
                if model_cls is not None and hasattr(model_cls, "organization_id"):
                    obj = model_cls.objects.filter(organization=org, id=int(oid)).first()
                else:
                    obj = model_cls.objects.filter(id=int(oid)).first() if model_cls is not None else None
                if obj:
                    attached_label = _human_ref_label(ct=ct, obj=obj)
                    attached_url = _url_for_object_detail(obj)
        except Exception:
            pass

    filename = a.filename or (Path(getattr(a.file, "name", "")).name if a.file else f"Attachment {a.id}")
    content_type = (mimetypes.guess_type(filename)[0] or "").lower()
    ext = Path(filename).suffix.lower().lstrip(".")

    preview_kind = None
    preview_text = None
    inline_url = reverse("ui:file_download", kwargs={"attachment_id": a.id}) + "?" + urlencode({"inline": "1"})

    if content_type.startswith("image/") and ext not in {"svg"}:
        preview_kind = "image"
    elif content_type == "application/pdf" or ext == "pdf":
        preview_kind = "pdf"
    elif content_type.startswith("text/") or ext in {"txt", "log", "md", "json", "yaml", "yml", "ini", "conf"}:
        preview_kind = "text"
        try:
            if a.file:
                with a.file.open("rb") as f:
                    raw = f.read(120_000)
                preview_text = raw.decode("utf-8", errors="replace")
        except Exception:
            preview_text = None

    size = None
    try:
        size = int(a.file.size) if a.file else None
    except Exception:
        size = None

    return render(
        request,
        "ui/file_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Files", reverse("ui:files_list")), (filename, None)),
            "a": a,
            "filename": filename,
            "size": size,
            "attached_label": attached_label,
            "attached_url": attached_url,
            "download_url": reverse("ui:file_download", kwargs={"attachment_id": a.id}),
            "inline_url": inline_url,
            "preview_kind": preview_kind,
            "preview_text": preview_text,
            "content_type": content_type or "application/octet-stream",
            "folders": list(FileFolder.objects.filter(organization=org, archived_at__isnull=True).select_related("parent").order_by("parent_id", "name")[:5000]),
            "tags": list(_tags_available_for_org(org)[:500]),
            "versions": list(a.versions.select_related("uploaded_by").order_by("-created_at")[:50]),
            "can_admin": can_admin,
            "is_reauthed": is_reauthed,
            "reauth_url": reauth_url,
            "share_new_url": share_new_url,
            "share_links": list(
                AttachmentShareLink.objects.filter(organization=org, attachment=a).select_related("created_by").order_by("-created_at")[:50]
            )
            if can_admin
            else [],
            "activity": _activity_for_object(org=org, model_cls=Attachment, obj_id=a.id),
        },
    )


@login_required
def file_download(request: HttpRequest, attachment_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    a = get_object_or_404(Attachment.objects.select_related("content_type"), id=attachment_id, organization=org)
    if not _can_view_attachment(request=request, org=org, a=a):
        raise PermissionDenied("Not allowed to download this file.")

    filename = a.filename or (Path(getattr(a.file, "name", "")).name if a.file else f"attachment-{a.id}")
    inline = (request.GET.get("inline") or "").strip().lower() in {"1", "true", "yes", "on"}
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    # FileResponse streams from storage efficiently. We still enforce auth/ACL here.
    try:
        f = a.file.open("rb")
    except Exception:
        raise PermissionDenied("File unavailable.")

    resp = FileResponse(f, as_attachment=not inline, filename=Path(filename).name, content_type=ctype)
    return resp


@login_required
def file_version_download(request: HttpRequest, attachment_id: int, version_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    a = get_object_or_404(Attachment, id=attachment_id, organization=org)
    if not _can_view_attachment(request=request, org=org, a=a):
        raise PermissionDenied("Not allowed to download this file.")
    v = get_object_or_404(AttachmentVersion, id=version_id, attachment=a)

    filename = v.filename or (Path(getattr(v.file, "name", "")).name if v.file else f"attachment-version-{v.id}")
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    try:
        f = v.file.open("rb")
    except Exception:
        raise PermissionDenied("File unavailable.")
    return FileResponse(f, as_attachment=True, filename=Path(filename).name, content_type=ctype)


@login_required
@require_POST
def file_version_restore(request: HttpRequest, attachment_id: int, version_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
        raise PermissionDenied("Not allowed.")
    if not _is_reauthed(request):
        nxt = reverse("ui:file_detail", kwargs={"attachment_id": attachment_id})
        return redirect(reverse("ui:reauth") + "?" + urlencode({"next": nxt}))

    a = get_object_or_404(Attachment, id=attachment_id, organization=org)
    if not _can_view_attachment(request=request, org=org, a=a):
        raise PermissionDenied("Not allowed.")
    v = get_object_or_404(AttachmentVersion, id=version_id, attachment=a)

    # Swap file pointers (no copy) so each DB row continues to own exactly one stored file.
    cur_name = getattr(a.file, "name", "") or ""
    cur_filename = a.filename or ""
    cur_bytes = None
    try:
        cur_bytes = int(a.file.size) if a.file else None
    except Exception:
        cur_bytes = None

    a.file.name = getattr(v.file, "name", "") or ""
    a.filename = v.filename or a.filename
    a.uploaded_by = request.user
    a.save(update_fields=["file", "filename", "uploaded_by", "updated_at"])

    v.file.name = cur_name
    v.filename = cur_filename
    v.bytes = cur_bytes
    v.uploaded_by = request.user
    v.save(update_fields=["file", "filename", "bytes", "uploaded_by"])

    return redirect("ui:file_detail", attachment_id=a.id)


@login_required
def file_version_delete(request: HttpRequest, attachment_id: int, version_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
        raise PermissionDenied("Not allowed.")
    a = get_object_or_404(Attachment, id=attachment_id, organization=org)
    v = get_object_or_404(AttachmentVersion, id=version_id, attachment=a)
    cancel_url = reverse("ui:file_detail", kwargs={"attachment_id": a.id})
    redirect_url = cancel_url

    def _go():
        v.delete()

    warning = "This deletes the version record and the underlying stored file."
    return _confirm_delete(
        request,
        org=org,
        kind="file version",
        label=v.filename or f"Version #{v.id}",
        cancel_url=cancel_url,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


@login_required
def relationship_delete(request: HttpRequest, relationship_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    rel = get_object_or_404(Relationship, id=relationship_id, organization=org)
    cancel = reverse("ui:relationship_detail", kwargs={"relationship_id": rel.id})
    redirect_url = reverse("ui:relationships_list")

    def _go():
        rel.delete()

    return _confirm_delete(
        request,
        org=org,
        kind="relationship",
        label=str(rel),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=None,
        on_confirm=_go,
    )

@login_required
def templates_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = DocumentTemplateForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            form.save_m2m()
            return redirect("ui:template_detail", template_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        form = DocumentTemplateForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Templates", reverse("ui:templates_list")), ("New", None)), "title": "New template", "form": form},
    )


@login_required
def template_detail(request: HttpRequest, template_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    tmpl = get_object_or_404(DocumentTemplate, id=template_id, organization=org)
    docs = Document.objects.filter(organization=org, template=tmpl).order_by("-updated_at")[:25]
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=tmpl, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:template_detail", template_id=tmpl.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=tmpl)
        return redirect(request.get_full_path())

    if request.method == "POST" and request.POST.get("_action") == "set_review_state":
        next_state = (request.POST.get("review_state") or "").strip()
        allowed_states = {DocumentTemplate.REVIEW_DRAFT, DocumentTemplate.REVIEW_IN_REVIEW, DocumentTemplate.REVIEW_APPROVED}
        if next_state in allowed_states:
            if next_state == DocumentTemplate.REVIEW_APPROVED and not _is_org_admin(request.user, org):
                raise PermissionDenied("Org admin role required to approve templates.")
            old_state = tmpl.review_state
            if old_state != next_state:
                tmpl.review_state = next_state
                if next_state == DocumentTemplate.REVIEW_DRAFT:
                    tmpl.reviewed_by = None
                    tmpl.reviewed_at = None
                else:
                    tmpl.reviewed_by = request.user
                    tmpl.reviewed_at = timezone.now()
                tmpl.save(update_fields=["review_state", "reviewed_by", "reviewed_at"])
                _audit_event(
                    request=request,
                    org=org,
                    action=AuditEvent.ACTION_UPDATE,
                    model="docsapp.DocumentTemplateReview",
                    object_pk=str(tmpl.id),
                    summary=f"Template review state changed: {_template_review_label(old_state)} -> {_template_review_label(next_state)}.",
                )
        return redirect("ui:template_detail", template_id=tmpl.id)

    if request.method == "POST" and request.POST.get("_action") == "add_comment":
        comment_form = DocumentTemplateCommentForm(request.POST, org=org)
        if comment_form.is_valid():
            comment = comment_form.save(commit=False)
            comment.organization = org
            comment.template = tmpl
            comment.created_by = request.user
            comment.save()
            _create_template_mention_notifications(org=org, tmpl=tmpl, comment=comment, actor=request.user)
            _audit_event(
                request=request,
                org=org,
                action=AuditEvent.ACTION_CREATE,
                model="docsapp.DocumentTemplateComment",
                object_pk=str(comment.id),
                summary=f"Comment added on template '{tmpl.name}'.",
            )
        return redirect("ui:template_detail", template_id=tmpl.id)

    if request.method == "POST" and request.POST.get("_action") == "delete_comment":
        try:
            comment_id = int(request.POST.get("comment_id") or "0")
        except Exception:
            comment_id = 0
        comment = get_object_or_404(DocumentTemplateComment, organization=org, template=tmpl, id=comment_id)
        if not (_is_org_admin(request.user, org) or (comment.created_by_id and int(comment.created_by_id) == int(request.user.id))):
            raise PermissionDenied("Not allowed.")
        _audit_event(
            request=request,
            org=org,
            action=AuditEvent.ACTION_DELETE,
            model="docsapp.DocumentTemplateComment",
            object_pk=str(comment.id),
            summary=f"Comment deleted from template '{tmpl.name}'.",
        )
        comment.delete()
        return redirect("ui:template_detail", template_id=tmpl.id)

    if request.method == "POST":
        form = DocumentTemplateForm(request.POST, instance=tmpl, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:template_detail", template_id=tmpl.id)
    else:
        form = DocumentTemplateForm(instance=tmpl, org=org)
    relationships = _relationships_for_object(org=org, obj=tmpl, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    edit_mode = _is_edit_mode(request)
    return render(
        request,
        "ui/template_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Templates", reverse("ui:templates_list")), (tmpl.name, None)),
            "template": tmpl,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:template_detail", kwargs={"template_id": tmpl.id}) + "?edit=1",
            "view_url": reverse("ui:template_detail", kwargs={"template_id": tmpl.id}),
            "can_admin": can_admin,
            "documents": docs,
            "attachments": _attachments_for_object(org=org, obj=tmpl),
            "notes": _notes_for_object(org=org, obj=tmpl),
            "comments": _comments_for_template(org=org, tmpl=tmpl, limit=200),
            "comment_form": DocumentTemplateCommentForm(org=org),
            "note_ref": _ref_for_obj(tmpl),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=DocumentTemplate),
            "custom_values": _custom_field_values_for_object(org=org, obj=tmpl),
            "activity": _activity_for_object(org=org, model_cls=DocumentTemplate, obj_id=tmpl.id),
            "versions": _versions_for_object(org=org, obj=tmpl, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(tmpl)}",
            "review_state_label": _template_review_label(tmpl.review_state),
        },
    )


@login_required
def template_delete(request: HttpRequest, template_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    tmpl = get_object_or_404(DocumentTemplate, id=template_id, organization=org)
    cancel = reverse("ui:template_detail", kwargs={"template_id": tmpl.id})
    redirect_url = reverse("ui:templates_list")

    def _go():
        if tmpl.archived_at is None:
            tmpl.archived_at = timezone.now()
            tmpl.save(update_fields=["archived_at"])

    warning = "Documents using this template will remain unchanged. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="template",
        label=str(tmpl),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )

@login_required
def passwords_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    rotation = (request.GET.get("rotation") or "").strip().lower()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_PASSWORD, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    folder_raw = (request.GET.get("folder") or "").strip()
    folder_id = int(folder_raw) if folder_raw.isdigit() else None
    folders = list(
        PasswordFolder.objects.filter(organization=org, archived_at__isnull=True)
        .select_related("parent")
        .order_by("parent_id", "name")[:5000]
    )
    qs = PasswordEntry.objects.filter(organization=org).select_related("folder").order_by("name")
    qs = _filter_archived_qs(request, qs)
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_passwords_q(request.user, org)).distinct()
    if folder_id:
        qs = qs.filter(folder_id=int(folder_id))
    if rotation:
        # Rotation is computed (last_changed_at + rotation_interval_days).
        # Use DB-side filtering on Postgres; fall back to best-effort Python filtering otherwise.
        today = timezone.localdate()
        if rotation == "enabled":
            qs = qs.filter(rotation_interval_days__gt=0)
        elif _is_postgres():
            try:
                from datetime import timedelta

                from django.db.models import DateTimeField, ExpressionWrapper, F, Value

                due_at = ExpressionWrapper(
                    F("last_changed_at") + (F("rotation_interval_days") * Value(timedelta(days=1))),
                    output_field=DateTimeField(),
                )
                qs = qs.annotate(_rotation_due_at=due_at).filter(rotation_interval_days__gt=0, last_changed_at__isnull=False)
                if rotation == "overdue":
                    qs = qs.filter(_rotation_due_at__date__lt=today)
                elif rotation == "due7":
                    qs = qs.filter(_rotation_due_at__date__lte=today + timedelta(days=7))
                elif rotation == "due30":
                    qs = qs.filter(_rotation_due_at__date__lte=today + timedelta(days=30))
            except Exception:
                pass
        else:
            # Non-Postgres: approximate via Python for the first N rows.
            # (Good enough for dev; real deployments use Postgres.)
            from datetime import timedelta

            tmp = list(qs.filter(rotation_interval_days__gt=0).order_by("name")[:2000])
            filtered = []
            for p in tmp:
                due = None
                try:
                    due = p.rotation_due_on()
                except Exception:
                    due = None
                if not due:
                    continue
                if rotation == "overdue" and due < today:
                    filtered.append(p)
                elif rotation == "due7" and due <= today + timedelta(days=7):
                    filtered.append(p)
                elif rotation == "due30" and due <= today + timedelta(days=30):
                    filtered.append(p)
            passwords = filtered[:200]
            due_map = {int(p.id): (p.rotation_due_on() if hasattr(p, "rotation_due_on") else None) for p in passwords}
            return render(
                request,
                "ui/passwords_list.html",
                {
                    "org": org,
                    "crumbs": _crumbs(("Passwords", None)),
                    "q": q,
                    "rotation": rotation,
                    "today": today,
                    "folders": folders,
                    "folder_id": folder_id,
                    "show_archived": show_archived,
                    "active_url": active_url,
                    "archived_url": archived_url,
                    "can_admin": can_admin,
                    "passwords": passwords,
                    "rotation_due": due_map,
                    "passwords_new_url": reverse("ui:passwords_new"),
                    "folders_url": reverse("ui:password_folders_list"),
                    "export_url": reverse("ui:passwords_export") + _qs_suffix(request),
                    "import_url": reverse("ui:passwords_import"),
                    "rel_counts": _relationship_counts_for_model(org=org, model_cls=PasswordEntry, ids=[p.id for p in passwords]),
                    "ref_prefix": _ref_prefix_for_model(PasswordEntry),
                    "tags_for_bulk": _tags_available_for_org(org)[:500],
                    "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_PASSWORD),
                    "active_view": active_view,
                    "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_PASSWORD, q=q),
                    "clear_view_url": reverse("ui:passwords_list"),
                },
            )
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(username__icontains=q) | Q(url__icontains=q) | Q(notes__icontains=q))
    passwords = list(qs[:200])
    due_map = {}
    try:
        due_map = {int(p.id): p.rotation_due_on() for p in passwords}
    except Exception:
        due_map = {}
    return render(
        request,
        "ui/passwords_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Passwords", None)),
            "q": q,
            "rotation": rotation,
            "today": timezone.localdate(),
            "folders": folders,
            "folder_id": folder_id,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "passwords": passwords,
            "rotation_due": due_map,
            "passwords_new_url": reverse("ui:passwords_new"),
            "folders_url": reverse("ui:password_folders_list"),
            "export_url": reverse("ui:passwords_export") + _qs_suffix(request),
            "import_url": reverse("ui:passwords_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=PasswordEntry, ids=[p.id for p in passwords]),
            "ref_prefix": _ref_prefix_for_model(PasswordEntry),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_PASSWORD),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_PASSWORD, q=q),
            "clear_view_url": reverse("ui:passwords_list"),
        },
    )

@login_required
def passwords_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert by (org, folder, name). If folder is blank, it upserts into the root (no folder).

    If `password` column is blank, existing password is unchanged.
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            required = {"name", "username", "url", "notes", "password"}
            if not reader.fieldnames or not required.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: name,username,url,notes,password (optional: folder,rotation_interval_days,last_changed_at)")
            else:
                for idx, row in enumerate(reader, start=2):
                    try:
                        name = (row.get("name") or "").strip()
                        if not name:
                            errors.append(f"Line {idx}: missing name")
                            continue
                        folder_name = (row.get("folder") or "").strip()
                        folder_obj = None
                        if folder_name:
                            folder_obj, _ = PasswordFolder.objects.get_or_create(organization=org, name=folder_name, parent=None)
                        username = (row.get("username") or "").strip()
                        url = (row.get("url") or "").strip()
                        notes = (row.get("notes") or "").strip()
                        pw = (row.get("password") or "")
                        pw = pw if pw is None else str(pw)
                        pw = pw.strip()
                        rot_raw = (row.get("rotation_interval_days") or "").strip()
                        rot_days = None
                        if rot_raw:
                            try:
                                rot_days = int(rot_raw)
                            except Exception:
                                errors.append(f"Line {idx}: invalid rotation_interval_days")
                                rot_days = None
                        last_changed_raw = (row.get("last_changed_at") or "").strip()
                        last_changed = None
                        if last_changed_raw:
                            try:
                                # Accept ISO format; timezone aware recommended.
                                last_changed = datetime.fromisoformat(last_changed_raw.replace("Z", "+00:00"))
                            except Exception:
                                errors.append(f"Line {idx}: invalid last_changed_at (expected ISO8601)")
                                last_changed = None

                        obj, was_created = PasswordEntry.objects.get_or_create(
                            organization=org,
                            folder=folder_obj,
                            name=name,
                            defaults={"username": username, "url": url, "notes": notes, "created_by": request.user},
                        )
                        if was_created:
                            if rot_days is not None:
                                obj.rotation_interval_days = max(0, int(rot_days))
                            if last_changed is not None:
                                obj.last_changed_at = last_changed
                            if pw:
                                obj.set_password(pw)
                                obj.save(update_fields=["password_ciphertext", "last_changed_at", "rotation_interval_days", "updated_at"])
                            else:
                                obj.save(update_fields=["rotation_interval_days", "last_changed_at", "updated_at"])
                            created += 1
                        else:
                            changed = False
                            for field, val in [("username", username), ("url", url), ("notes", notes)]:
                                if getattr(obj, field) != val:
                                    setattr(obj, field, val)
                                    changed = True
                            if rot_days is not None and int(obj.rotation_interval_days or 0) != int(rot_days):
                                obj.rotation_interval_days = max(0, int(rot_days))
                                changed = True
                            if last_changed is not None and getattr(obj, "last_changed_at", None) != last_changed:
                                obj.last_changed_at = last_changed
                                changed = True
                            if pw:
                                obj.set_password(pw)
                                changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/passwords_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/passwords_import.html",
        {"org": org, "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )

@login_required
def passwords_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_PASSWORD, q=q)
    qs = PasswordEntry.objects.filter(organization=org).select_related("folder").order_by("name")
    qs = _filter_archived_qs(request, qs)
    if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_passwords_q(request.user, org)).distinct()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(username__icontains=q) | Q(url__icontains=q) | Q(notes__icontains=q))
    rows = []
    for p in qs[:5000]:
        rows.append(
            [
                p.name or "",
                p.folder.name if p.folder_id else "",
                p.username or "",
                p.url or "",
                str(int(getattr(p, "rotation_interval_days", 0) or 0)),
                (p.last_changed_at.isoformat() if getattr(p, "last_changed_at", None) else ""),
                p.updated_at.isoformat() if p.updated_at else "",
            ]
        )
    return _csv_http_response(
        filename=f"{org.name}-passwords.csv",
        header=["name", "folder", "username", "url", "rotation_interval_days", "last_changed_at", "updated_at"],
        rows=rows,
    )

@login_required
@require_POST
def passwords_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    action = (request.POST.get("action") or "").strip()
    if action == "mark_rotated":
        # Sensitive-ish bulk action: require org admin + recent re-auth.
        _require_org_admin(request.user, org)
        if not _is_reauthed(request):
            nxt = (request.POST.get("next") or "").strip() or reverse("ui:passwords_list")
            return redirect(reverse("ui:reauth") + "?" + urlencode({"next": nxt}))

        ids = [int(x) for x in request.POST.getlist("ids") if (x or "").isdigit()]
        if ids:
            now = timezone.now()
            PasswordEntry.objects.filter(organization=org, id__in=ids).update(last_changed_at=now, updated_at=now)
        return _redirect_back(request, fallback_url=reverse("ui:passwords_list"))

    return _bulk_action(
        request,
        org=org,
        model_cls=PasswordEntry,
        base_qs=PasswordEntry.objects.filter(organization=org),
        list_url_name="ui:passwords_list",
        supports_tags=True,
    )


@login_required
def password_folders_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)

    qs = PasswordFolder.objects.filter(organization=org).order_by("parent_id", "name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q))
    folders = list(qs[:5000])
    return render(
        request,
        "ui/password_folders_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), ("Folders", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "folders": folders,
            "new_url": reverse("ui:password_folder_new"),
            "bulk_url": reverse("ui:password_folders_bulk"),
        },
    )


@login_required
def password_folder_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = PasswordFolderForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:password_folder_detail", folder_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        parent = (request.GET.get("parent") or "").strip()
        if parent.isdigit():
            init["parent"] = int(parent)
        form = PasswordFolderForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), ("Folders", reverse("ui:password_folders_list")), ("New", None)), "title": "New password folder", "form": form},
    )


@login_required
def password_folder_detail(request: HttpRequest, folder_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    folder = get_object_or_404(PasswordFolder, organization=org, id=folder_id)

    if request.method == "POST":
        form = PasswordFolderForm(request.POST, instance=folder, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:password_folder_detail", folder_id=folder.id)
    else:
        form = PasswordFolderForm(instance=folder, org=org)

    pqs = PasswordEntry.objects.filter(organization=org, folder=folder, archived_at__isnull=True).order_by("name")
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        pqs = pqs.filter(_visible_passwords_q(request.user, org)).distinct()
    entries = list(pqs[:200])

    return render(
        request,
        "ui/password_folder_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), ("Folders", reverse("ui:password_folders_list")), (folder.name, None)),
            "folder": folder,
            "form": form,
            "can_admin": can_admin,
            "entries": entries,
        },
    )


@login_required
def password_folder_delete(request: HttpRequest, folder_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    folder = get_object_or_404(PasswordFolder, organization=org, id=folder_id)
    cancel = reverse("ui:password_folder_detail", kwargs={"folder_id": folder.id})
    redirect_url = reverse("ui:password_folders_list")

    def _go():
        if folder.archived_at is None:
            folder.archived_at = timezone.now()
            folder.save(update_fields=["archived_at"])

    warning = "Passwords remain and will keep their folder reference unless you move them. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="password folder",
        label=str(folder),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
@require_POST
def password_folders_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=PasswordFolder,
        base_qs=PasswordFolder.objects.filter(organization=org),
        list_url_name="ui:password_folders_list",
        supports_tags=False,
    )


@login_required
def passwords_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = PasswordEntryForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.created_by = request.user
            obj.save()
            form.save_m2m()
            if obj.visibility != PasswordEntry.VIS_SHARED:
                obj.allowed_users.clear()
            return redirect("ui:password_detail", password_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        folder = (request.GET.get("folder") or "").strip()
        if folder.isdigit():
            init["folder"] = int(folder)
        form = PasswordEntryForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), ("New", None)), "title": "New password entry", "form": form},
    )


@login_required
def password_detail(request: HttpRequest, password_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    qs = PasswordEntry.objects.filter(organization=org)
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_passwords_q(request.user, org)).distinct()
    entry = get_object_or_404(qs, id=password_id)

    reveal = None
    can_reveal = _can_view_password(user=request.user, org=org, entry=entry)
    is_reauthed = _is_reauthed(request)
    sess_key_secret = f"pw_totp_new_secret:{entry.id}"
    sess_key_uri = f"pw_totp_new_uri:{entry.id}"
    totp_new_secret = request.session.pop(sess_key_secret, None)
    totp_new_uri = request.session.pop(sess_key_uri, None)
    sess_key_share = f"pw_share_new_url:{entry.id}"
    share_new_url = request.session.pop(sess_key_share, None)
    reauth_url = reverse("ui:reauth") + "?" + urlencode({"next": request.get_full_path()})

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=entry, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:password_detail", password_id=entry.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=entry)
        return redirect(request.get_full_path())

    if request.method == "POST" and request.POST.get("_action") == "mark_rotated":
        if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)):
            raise PermissionDenied("Only org admins can mark rotations.")
        if not is_reauthed:
            return redirect(reauth_url)
        entry.last_changed_at = timezone.now()
        entry.save(update_fields=["last_changed_at", "updated_at"])
        return redirect("ui:password_detail", password_id=entry.id)

    if request.method == "POST" and request.POST.get("_action") in ["enable_totp", "rotate_totp", "disable_totp"]:
        if not can_reveal:
            raise PermissionDenied("Not allowed to manage OTP for this password.")
        if not is_reauthed:
            return redirect(reauth_url)
        action = request.POST.get("_action")
        if action == "disable_totp":
            if entry.has_totp():
                entry.clear_totp()
                entry.save(update_fields=["totp_secret_ciphertext", "updated_at"])
            return redirect("ui:password_detail", password_id=entry.id)

        # enable_totp / rotate_totp
        secret = generate_base32_secret()
        entry.set_totp_secret(secret)
        # Keep defaults for now; make these editable later.
        entry.totp_digits = 6
        entry.totp_period = 30
        entry.totp_algorithm = "SHA1"
        entry.save(update_fields=["totp_secret_ciphertext", "totp_digits", "totp_period", "totp_algorithm", "updated_at"])

        acct = entry.username or entry.name
        uri = build_otpauth_url(
            issuer="HomeGlue",
            account_name=f"{org.name} / {acct}",
            secret_b32=secret,
            digits=entry.totp_digits,
            period=entry.totp_period,
            algorithm=entry.totp_algorithm,
        )
        request.session[sess_key_secret] = secret
        request.session[sess_key_uri] = uri
        request.session.modified = True
        return redirect("ui:password_detail", password_id=entry.id)

    if request.method == "POST" and request.POST.get("_action") == "share_create":
        if not can_reveal:
            raise PermissionDenied("Not allowed to share this password.")
        if not can_admin and not getattr(request.user, "is_superuser", False):
            raise PermissionDenied("Only org admins can create share links.")
        if not is_reauthed:
            return redirect(reauth_url)

        try:
            hours = int(request.POST.get("expires_in_hours") or 24)
        except Exception:
            hours = 24
        hours = max(1, min(24 * 90, int(hours)))
        one_time = (request.POST.get("one_time") or "").strip() == "1"
        label = (request.POST.get("label") or "").strip()

        expires_at = timezone.now() + timedelta(hours=hours)
        token = ""
        for _ in range(3):
            token = PasswordShareLink.build_new_token()
            token_hash = PasswordShareLink.hash_token(token)
            try:
                PasswordShareLink.objects.create(
                    organization=org,
                    password_entry=entry,
                    created_by=request.user if request.user.is_authenticated else None,
                    label=label,
                    token_hash=token_hash,
                    token_prefix=(token[:12] if token else ""),
                    expires_at=expires_at,
                    one_time=one_time,
                )
                break
            except IntegrityError:
                token = ""
                continue
        if not token:
            raise PermissionDenied("Unable to create share link (try again).")
        base_url = (get_base_url() or "").strip().rstrip("/")
        if not base_url:
            base_url = request.build_absolute_uri("/").rstrip("/")
        share_url = f"{base_url}{reverse('public:password_share', kwargs={'token': token})}"
        request.session[sess_key_share] = share_url
        request.session.modified = True
        return redirect("ui:password_detail", password_id=entry.id)

    if request.method == "POST" and request.POST.get("_action") == "share_revoke":
        if not can_reveal:
            raise PermissionDenied("Not allowed.")
        if not can_admin and not getattr(request.user, "is_superuser", False):
            raise PermissionDenied("Only org admins can revoke share links.")
        if not is_reauthed:
            return redirect(reauth_url)
        sid = (request.POST.get("share_id") or "").strip()
        if sid.isdigit():
            sl = PasswordShareLink.objects.filter(organization=org, password_entry=entry, id=int(sid)).first()
            if sl and not sl.revoked_at:
                sl.revoked_at = timezone.now()
                sl.save(update_fields=["revoked_at"])
        return redirect("ui:password_detail", password_id=entry.id)

    if request.method == "POST" and request.POST.get("_action") == "reveal":
        if not can_reveal:
            raise PermissionDenied("Not allowed to reveal this password.")
        if not is_reauthed:
            return redirect(reauth_url)
        reveal = entry.get_password()

    if request.method == "POST" and request.POST.get("_action") == "save":
        form = PasswordEntryForm(request.POST, instance=entry, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:password_detail", password_id=entry.id)
    else:
        form = PasswordEntryForm(instance=entry, org=org)

    edit_mode = _is_edit_mode(request)
    relationships = _relationships_for_object(org=org, obj=entry, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    share_links = []
    if can_admin or getattr(request.user, "is_superuser", False):
        share_links = list(PasswordShareLink.objects.filter(organization=org, password_entry=entry).select_related("created_by").order_by("-created_at")[:50])

    rotation_due_on = None
    rotation_overdue = False
    try:
        rotation_due_on = entry.rotation_due_on()
        if rotation_due_on:
            rotation_overdue = rotation_due_on < timezone.now().date()
    except Exception:
        rotation_due_on = None
        rotation_overdue = False
    return render(
        request,
        "ui/password_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Passwords", reverse("ui:passwords_list")), (entry.name, None)),
            "entry": entry,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:password_detail", kwargs={"password_id": entry.id}) + "?edit=1",
            "view_url": reverse("ui:password_detail", kwargs={"password_id": entry.id}),
            "can_admin": can_admin,
            "reveal": reveal,
            "can_reveal": can_reveal,
            "is_reauthed": is_reauthed,
            "reauth_url": reauth_url,
            "totp_enabled": entry.has_totp(),
            "totp_code_url": reverse("ui:password_totp_code", kwargs={"password_id": entry.id}),
            "totp_new_secret": totp_new_secret,
            "totp_new_uri": totp_new_uri,
            "share_links": share_links,
            "share_new_url": share_new_url,
            "rotation_due_on": rotation_due_on,
            "rotation_overdue": rotation_overdue,
            "attachments": _attachments_for_object(org=org, obj=entry),
            "notes": _notes_for_object(org=org, obj=entry),
            "note_ref": _ref_for_obj(entry),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=PasswordEntry),
            "custom_values": _custom_field_values_for_object(org=org, obj=entry),
            "activity": _activity_for_object(org=org, model_cls=PasswordEntry, obj_id=entry.id),
            "versions": _versions_for_object(org=org, obj=entry, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(entry)}",
            "now": timezone.now(),
        },
    )


@login_required
def password_totp_code(request: HttpRequest, password_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    qs = PasswordEntry.objects.filter(organization=org)
    if not (can_admin or getattr(request.user, "is_superuser", False)):
        qs = qs.filter(_visible_passwords_q(request.user, org)).distinct()
    entry = get_object_or_404(qs, id=password_id)

    if not _can_view_password(user=request.user, org=org, entry=entry):
        raise PermissionDenied("Not allowed.")
    if not _is_reauthed(request):
        return JsonResponse({"detail": "reauth_required"}, status=403)
    if not entry.has_totp():
        return JsonResponse({"detail": "TOTP not enabled."}, status=404)
    try:
        code, remaining = entry.get_totp_code()
    except TotpError as e:
        return JsonResponse({"detail": str(e)}, status=400)
    return JsonResponse(
        {
            "code": code,
            "remaining": int(remaining),
            "period": int(entry.totp_period or 30),
            "digits": int(entry.totp_digits or 6),
            "algorithm": (entry.totp_algorithm or "SHA1"),
        }
    )


@login_required
def password_delete(request: HttpRequest, password_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    entry = get_object_or_404(PasswordEntry, id=password_id, organization=org)
    cancel = reverse("ui:password_detail", kwargs={"password_id": entry.id})
    redirect_url = reverse("ui:passwords_list")

    def _go():
        if entry.archived_at is None:
            entry.archived_at = timezone.now()
            entry.save(update_fields=["archived_at"])

    warning = "Relationships, notes, and attachments will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="password entry",
        label=str(entry),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


def _expiry_badge(expires_on) -> dict[str, str] | None:
    """
    Return a small status badge descriptor for an expiry date.
    """

    if not expires_on:
        return None
    try:
        from datetime import date

        today = date.today()
        days = (expires_on - today).days
    except Exception:
        return None

    if days < 0:
        return {"label": "Expired", "tone": "danger"}
    if days <= 14:
        return {"label": f"{days}d", "tone": "danger"}
    if days <= 30:
        return {"label": f"{days}d", "tone": "warn"}
    if days <= 90:
        return {"label": f"{days}d", "tone": "ok"}
    return {"label": f"{days}d", "tone": "muted"}


@login_required
def domains_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_DOMAIN, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = Domain.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q) | Q(notes__icontains=q))
    domains = list(qs[:200])
    return render(
        request,
        "ui/domains_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Domains", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "domains": domains,
            "domains_new_url": reverse("ui:domains_new"),
            "export_url": reverse("ui:domains_export") + _qs_suffix(request),
            "import_url": reverse("ui:domains_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=Domain, ids=[d.id for d in domains]),
            "ref_prefix": _ref_prefix_for_model(Domain),
            "expiry_badges": {int(d.id): _expiry_badge(d.expires_on) for d in domains},
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_DOMAIN),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_DOMAIN, q=q),
            "clear_view_url": reverse("ui:domains_list"),
        },
    )


@login_required
def domains_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert by (org, name).

    Headers:
      name,status,registrar,dns_provider,expires_on,auto_renew,notes
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"name", "status", "registrar", "dns_provider", "expires_on", "auto_renew", "notes"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append("CSV must include headers: name,status,registrar,dns_provider,expires_on,auto_renew,notes")
            else:
                for idx, row in enumerate(reader, start=2):
                    try:
                        name = (row.get("name") or "").strip()
                        if not name:
                            errors.append(f"Line {idx}: missing name")
                            continue
                        status = (row.get("status") or "").strip() or Domain.STATUS_ACTIVE
                        registrar = (row.get("registrar") or "").strip()
                        dns_provider = (row.get("dns_provider") or "").strip()
                        notes = (row.get("notes") or "").strip()

                        expires_raw = (row.get("expires_on") or "").strip()
                        expires_on = None
                        if expires_raw:
                            from datetime import date

                            expires_on = date.fromisoformat(expires_raw)

                        ar = (row.get("auto_renew") or "").strip().lower()
                        auto_renew = ar in {"1", "true", "yes", "y", "on"}

                        obj, was_created = Domain.objects.get_or_create(
                            organization=org,
                            name=name,
                            defaults={
                                "status": status,
                                "registrar": registrar,
                                "dns_provider": dns_provider,
                                "expires_on": expires_on,
                                "auto_renew": auto_renew,
                                "notes": notes,
                            },
                        )
                        if was_created:
                            created += 1
                        else:
                            changed = False
                            for field, val in [
                                ("status", status),
                                ("registrar", registrar),
                                ("dns_provider", dns_provider),
                                ("expires_on", expires_on),
                                ("auto_renew", auto_renew),
                                ("notes", notes),
                            ]:
                                if getattr(obj, field) != val:
                                    setattr(obj, field, val)
                                    changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/domains_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("Domains", reverse("ui:domains_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/domains_import.html",
        {"org": org, "crumbs": _crumbs(("Domains", reverse("ui:domains_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )


@login_required
def domains_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_DOMAIN, q=q)
    qs = Domain.objects.filter(organization=org).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(registrar__icontains=q) | Q(dns_provider__icontains=q) | Q(notes__icontains=q))
    rows = []
    for d in qs[:5000]:
        rows.append(
            [
                d.name or "",
                d.status or "",
                d.registrar or "",
                d.dns_provider or "",
                d.expires_on.isoformat() if d.expires_on else "",
                "true" if d.auto_renew else "false",
                d.notes or "",
            ]
        )
    return _csv_http_response(
        filename=f"{org.name}-domains.csv",
        header=["name", "status", "registrar", "dns_provider", "expires_on", "auto_renew", "notes"],
        rows=rows,
    )


@login_required
@require_POST
def domains_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=Domain,
        base_qs=Domain.objects.filter(organization=org),
        list_url_name="ui:domains_list",
        supports_tags=True,
    )


@login_required
def domains_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip().lower()
        if action == "lookup_public":
            data = request.POST.copy()
            form0 = DomainForm(data, org=org)
            filled_any = False
            if form0.is_valid():
                # Best-effort: fill only missing public fields from RDAP without saving.
                try:
                    name = (form0.cleaned_data.get("name") or "").strip()
                    info = lookup_domain_rdap(name)
                    tmp = Domain(
                        organization=org,
                        name=name,
                        registrar=(form0.cleaned_data.get("registrar") or ""),
                        expires_on=form0.cleaned_data.get("expires_on"),
                    )
                    filled_any = bool(apply_domain_public_info(obj=tmp, info=info, force=False))
                    if not (data.get("registrar") or "").strip() and (tmp.registrar or "").strip():
                        data["registrar"] = tmp.registrar
                        filled_any = True
                    if not (data.get("expires_on") or "").strip() and isinstance(tmp.expires_on, date):
                        data["expires_on"] = tmp.expires_on.isoformat()
                        filled_any = True
                except Exception:
                    pass
            form = DomainForm(data, org=org)
            return render(
                request,
                "ui/form.html",
                {
                    "org": org,
                    "crumbs": _crumbs(("Domains", reverse("ui:domains_list")), ("New", None)),
                    "title": "New domain",
                    "form": form,
                    "submit_label": "Create",
                    "submit_icon": "#i-plus",
                    "primary_action": "create",
                    "secondary_submit_buttons": [{"label": "Lookup", "name": "_action", "value": "lookup_public", "icon": "#i-bolt"}],
                    "notice": (
                        {"title": "Lookup complete", "body": "We filled in any missing public info we could find for that domain."}
                        if filled_any
                        else {
                            "title": "No public info found",
                            "body": "We couldn't find public RDAP info for that domain. If it's a private/internal domain, you'll need to enter details manually.",
                        }
                    ),
                },
            )

        form = DomainForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            # Best-effort: auto-populate missing public info on create.
            auto_changed = False
            try:
                if obj.expires_on is None or not (obj.registrar or "").strip():
                    info = lookup_domain_rdap(obj.name)
                    auto_changed = bool(apply_domain_public_info(obj=obj, info=info, force=False))
            except Exception:
                pass
            obj.save()
            form.save_m2m()
            if (obj.name or "").strip():
                if auto_changed:
                    request.session["homeglue_flash"] = {
                        "title": "Auto-filled domain info",
                        "body": "We pulled in public RDAP data for this domain where available.",
                    }
                else:
                    request.session["homeglue_flash"] = {
                        "title": "No public domain info found",
                        "body": "We couldn't find public RDAP data for that domain. If it's internal, that's expected.",
                    }
            return redirect("ui:domain_detail", domain_id=obj.id)
    else:
        init = {}
        name = (request.GET.get("name") or "").strip()
        if name:
            init["name"] = name
        form = DomainForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("Domains", reverse("ui:domains_list")), ("New", None)),
            "title": "New domain",
            "form": form,
            "submit_label": "Create",
            "submit_icon": "#i-plus",
            "primary_action": "create",
            "secondary_submit_buttons": [{"label": "Lookup", "name": "_action", "value": "lookup_public", "icon": "#i-bolt"}],
        },
    )


@login_required
def domain_detail(request: HttpRequest, domain_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    dom = get_object_or_404(Domain, id=domain_id, organization=org)
    can_admin = _is_org_admin(request.user, org)
    flash = request.session.pop("homeglue_flash", None)

    if request.method == "POST" and request.POST.get("_action") == "refresh_public":
        changed = False
        try:
            info = lookup_domain_rdap(dom.name)
            changed = bool(apply_domain_public_info(obj=dom, info=info, force=True))
            if changed:
                dom.save()
        except Exception:
            request.session["homeglue_flash"] = {"title": "Refresh failed", "body": "Unable to fetch public RDAP info right now."}
            return redirect("ui:domain_detail", domain_id=dom.id)
        request.session["homeglue_flash"] = (
            {"title": "Refreshed", "body": "Updated domain public info from RDAP."}
            if changed
            else {"title": "No updates", "body": "No additional public RDAP info was found for this domain."}
        )
        return redirect("ui:domain_detail", domain_id=dom.id)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=dom, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:domain_detail", domain_id=dom.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=dom)
        return redirect(request.get_full_path())

    if request.method == "POST":
        form = DomainForm(request.POST, instance=dom, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            # Best-effort: if user left public fields blank, fill them.
            try:
                if obj.expires_on is None or not (obj.registrar or "").strip():
                    info = lookup_domain_rdap(obj.name)
                    apply_domain_public_info(obj=obj, info=info, force=False)
            except Exception:
                pass
            obj.save()
            form.save_m2m()
            return redirect("ui:domain_detail", domain_id=dom.id)
    else:
        form = DomainForm(instance=dom, org=org)

    edit_mode = _is_edit_mode(request)
    relationships = _relationships_for_object(org=org, obj=dom, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/domain_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Domains", reverse("ui:domains_list")), (dom.name, None)),
            "domain": dom,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:domain_detail", kwargs={"domain_id": dom.id}) + "?edit=1",
            "view_url": reverse("ui:domain_detail", kwargs={"domain_id": dom.id}),
            "can_admin": can_admin,
            "flash": flash,
            "expiry_badge": _expiry_badge(dom.expires_on),
            "attachments": _attachments_for_object(org=org, obj=dom),
            "notes": _notes_for_object(org=org, obj=dom),
            "note_ref": _ref_for_obj(dom),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=Domain),
            "custom_values": _custom_field_values_for_object(org=org, obj=dom),
            "activity": _activity_for_object(org=org, model_cls=Domain, obj_id=dom.id),
            "versions": _versions_for_object(org=org, obj=dom, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(dom)}",
        },
    )


@login_required
def domain_delete(request: HttpRequest, domain_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    dom = get_object_or_404(Domain, id=domain_id, organization=org)
    cancel = reverse("ui:domain_detail", kwargs={"domain_id": dom.id})
    redirect_url = reverse("ui:domains_list")

    def _go():
        if dom.archived_at is None:
            dom.archived_at = timezone.now()
            dom.save(update_fields=["archived_at"])

    warning = "Relationships, notes, and attachments will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="domain",
        label=str(dom),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
def sslcerts_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    q, active_view = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_SSL_CERT, q=q)
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = SSLCertificate.objects.filter(organization=org).annotate(dom_count=Count("domains", distinct=True)).order_by("not_after", "common_name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(
            Q(common_name__icontains=q)
            | Q(subject_alt_names__icontains=q)
            | Q(issuer__icontains=q)
            | Q(serial_number__icontains=q)
            | Q(fingerprint_sha256__icontains=q)
            | Q(notes__icontains=q)
        )
    certs = list(qs[:200])
    return render(
        request,
        "ui/sslcerts_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("SSL Certificates", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "certs": certs,
            "sslcerts_new_url": reverse("ui:sslcerts_new"),
            "export_url": reverse("ui:sslcerts_export") + _qs_suffix(request),
            "import_url": reverse("ui:sslcerts_import"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=SSLCertificate, ids=[c.id for c in certs]),
            "ref_prefix": _ref_prefix_for_model(SSLCertificate),
            "expiry_badges": {int(c.id): _expiry_badge(c.not_after) for c in certs},
            "tags_for_bulk": _tags_available_for_org(org)[:500],
            "saved_views": _saved_views_for(org=org, model_key=SavedView.KEY_SSL_CERT),
            "active_view": active_view,
            "save_view_url": _save_view_new_url(request=request, model_key=SavedView.KEY_SSL_CERT, q=q),
            "clear_view_url": reverse("ui:sslcerts_list"),
        },
    )


@login_required
def sslcerts_import(request: HttpRequest) -> HttpResponse:
    """
    Upsert by fingerprint_sha256 if present, else (common_name, not_after).

    Headers:
      common_name,subject_alt_names,issuer,serial_number,fingerprint_sha256,not_before,not_after,domains,notes

    `domains` is a comma-separated list of domain names; missing domains are created.
    """
    ctx = require_current_org(request)
    org = ctx.organization

    created = 0
    updated = 0
    errors: list[str] = []

    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            errors.append("No file uploaded.")
        else:
            raw = f.read()
            try:
                text = raw.decode("utf-8-sig")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            reader = csv.DictReader(io.StringIO(text))
            expected = {"common_name", "subject_alt_names", "issuer", "serial_number", "fingerprint_sha256", "not_before", "not_after", "domains", "notes"}
            if not reader.fieldnames or not expected.issubset(set([h.strip() for h in reader.fieldnames if h])):
                errors.append(
                    "CSV must include headers: common_name,subject_alt_names,issuer,serial_number,fingerprint_sha256,not_before,not_after,domains,notes"
                )
            else:
                for idx, row in enumerate(reader, start=2):
                    try:
                        cn = (row.get("common_name") or "").strip()
                        san = (row.get("subject_alt_names") or "").strip()
                        issuer = (row.get("issuer") or "").strip()
                        serial = (row.get("serial_number") or "").strip()
                        fp = (row.get("fingerprint_sha256") or "").strip()
                        notes = (row.get("notes") or "").strip()

                        nb_raw = (row.get("not_before") or "").strip()
                        na_raw = (row.get("not_after") or "").strip()

                        nb = None
                        na = None
                        from datetime import date

                        if nb_raw:
                            nb = date.fromisoformat(nb_raw)
                        if na_raw:
                            na = date.fromisoformat(na_raw)

                        doms_raw = (row.get("domains") or "").strip()
                        dom_names = [x.strip() for x in doms_raw.split(",") if x.strip()] if doms_raw else []
                        dom_ids = []
                        for dn in dom_names:
                            d, _ = Domain.objects.get_or_create(organization=org, name=dn)
                            dom_ids.append(d.id)

                        obj = None
                        if fp:
                            obj = SSLCertificate.objects.filter(organization=org, fingerprint_sha256=fp).first()
                        if obj is None and cn and na is not None:
                            obj = SSLCertificate.objects.filter(organization=org, common_name=cn, not_after=na).first()

                        if obj is None:
                            obj = SSLCertificate.objects.create(
                                organization=org,
                                common_name=cn,
                                subject_alt_names=san,
                                issuer=issuer,
                                serial_number=serial,
                                fingerprint_sha256=fp,
                                not_before=nb,
                                not_after=na,
                                notes=notes,
                            )
                            if dom_ids:
                                obj.domains.set(dom_ids)
                            created += 1
                        else:
                            changed = False
                            for field, val in [
                                ("common_name", cn),
                                ("subject_alt_names", san),
                                ("issuer", issuer),
                                ("serial_number", serial),
                                ("fingerprint_sha256", fp),
                                ("not_before", nb),
                                ("not_after", na),
                                ("notes", notes),
                            ]:
                                if getattr(obj, field) != val:
                                    setattr(obj, field, val)
                                    changed = True
                            if dom_ids:
                                existing_ids = set(obj.domains.values_list("id", flat=True))
                                if set(dom_ids) != existing_ids:
                                    obj.domains.set(dom_ids)
                                    changed = True
                            if changed:
                                obj.save()
                                updated += 1
                    except Exception as e:
                        errors.append(f"Line {idx}: {e}")

        return render(
            request,
            "ui/sslcerts_import.html",
            {
                "org": org,
                "crumbs": _crumbs(("SSL Certificates", reverse("ui:sslcerts_list")), ("Import", None)),
                "created": created,
                "updated": updated,
                "errors": errors,
            },
        )

    return render(
        request,
        "ui/sslcerts_import.html",
        {"org": org, "crumbs": _crumbs(("SSL Certificates", reverse("ui:sslcerts_list")), ("Import", None)), "created": None, "updated": None, "errors": None},
    )


@login_required
def sslcerts_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    q, _ = _apply_saved_view_q(request=request, org=org, model_key=SavedView.KEY_SSL_CERT, q=q)
    qs = SSLCertificate.objects.prefetch_related("domains").filter(organization=org).order_by("not_after", "common_name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(
            Q(common_name__icontains=q)
            | Q(subject_alt_names__icontains=q)
            | Q(issuer__icontains=q)
            | Q(serial_number__icontains=q)
            | Q(fingerprint_sha256__icontains=q)
            | Q(notes__icontains=q)
        )
    rows = []
    for c in qs[:5000]:
        rows.append(
            [
                c.common_name or "",
                c.subject_alt_names or "",
                c.issuer or "",
                c.serial_number or "",
                c.fingerprint_sha256 or "",
                c.not_before.isoformat() if c.not_before else "",
                c.not_after.isoformat() if c.not_after else "",
                ", ".join(list(c.domains.order_by("name").values_list("name", flat=True))),
                c.notes or "",
            ]
        )
    return _csv_http_response(
        filename=f"{org.name}-ssl-certs.csv",
        header=["common_name", "subject_alt_names", "issuer", "serial_number", "fingerprint_sha256", "not_before", "not_after", "domains", "notes"],
        rows=rows,
    )


@login_required
@require_POST
def sslcerts_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=SSLCertificate,
        base_qs=SSLCertificate.objects.filter(organization=org),
        list_url_name="ui:sslcerts_list",
        supports_tags=True,
    )


@login_required
def sslcerts_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        action = (request.POST.get("_action") or "").strip().lower()
        if action == "lookup_public":
            data = request.POST.copy()
            form0 = SSLCertificateForm(data, org=org)
            filled_any = False
            if form0.is_valid():
                # Best-effort: fill only missing public fields from TLS lookup without saving.
                try:
                    cn = (form0.cleaned_data.get("common_name") or "").strip()
                    info = lookup_tls_certificate(cn)
                    if info:
                        tmp = SSLCertificate(
                            organization=org,
                            common_name=cn,
                            issuer=(form0.cleaned_data.get("issuer") or ""),
                            serial_number=(form0.cleaned_data.get("serial_number") or ""),
                            fingerprint_sha256=(form0.cleaned_data.get("fingerprint_sha256") or ""),
                            not_before=form0.cleaned_data.get("not_before"),
                            not_after=form0.cleaned_data.get("not_after"),
                            subject_alt_names=(form0.cleaned_data.get("subject_alt_names") or ""),
                        )
                        filled_any = bool(apply_ssl_public_info(obj=tmp, info=info, force=False))
                        for k, v in [
                            ("issuer", tmp.issuer),
                            ("serial_number", tmp.serial_number),
                            ("fingerprint_sha256", tmp.fingerprint_sha256),
                            ("subject_alt_names", tmp.subject_alt_names),
                        ]:
                            if not (data.get(k) or "").strip() and (v or "").strip():
                                data[k] = v
                                filled_any = True
                        if not (data.get("not_before") or "").strip() and isinstance(tmp.not_before, date):
                            data["not_before"] = tmp.not_before.isoformat()
                            filled_any = True
                        if not (data.get("not_after") or "").strip() and isinstance(tmp.not_after, date):
                            data["not_after"] = tmp.not_after.isoformat()
                            filled_any = True
                except Exception:
                    pass
            form = SSLCertificateForm(data, org=org)
            return render(
                request,
                "ui/form.html",
                {
                    "org": org,
                    "crumbs": _crumbs(("SSL Certificates", reverse("ui:sslcerts_list")), ("New", None)),
                    "title": "New SSL certificate",
                    "form": form,
                    "submit_label": "Create",
                    "submit_icon": "#i-plus",
                    "primary_action": "create",
                    "secondary_submit_buttons": [{"label": "Lookup", "name": "_action", "value": "lookup_public", "icon": "#i-bolt"}],
                    "notice": (
                        {"title": "Lookup complete", "body": "We filled in any missing public cert info we could fetch from the common name."}
                        if filled_any
                        else {
                            "title": "No cert info found",
                            "body": "We couldn't fetch certificate metadata from that common name. If it's internal/unreachable, that's expected. You can try using host:port or enter details manually.",
                        }
                    ),
                },
            )

        form = SSLCertificateForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            # Save first so we can M2M link domains even if lookup fails.
            obj.save()
            form.save_m2m()
            # Best-effort: auto-populate certificate details and link domains.
            auto_changed = False
            linked = 0
            info_found = False
            try:
                if (obj.common_name or "").strip():
                    info = lookup_tls_certificate(obj.common_name)
                    if info:
                        info_found = True
                        if apply_ssl_public_info(obj=obj, info=info, force=False):
                            auto_changed = True
                            obj.save()
                        for name in dns_names_for_cert(common_name=obj.common_name, info=info):
                            d, _ = Domain.objects.get_or_create(organization=org, name=name)
                            if not obj.domains.filter(id=d.id).exists():
                                obj.domains.add(d)
                                linked += 1
            except Exception:
                pass
            cn_label = (obj.common_name or "").strip() or "that host"
            if info_found:
                parts = []
                if auto_changed:
                    parts.append("filled in missing certificate fields")
                if linked:
                    parts.append(f"linked {linked} domain(s)")
                body = "We " + (" and ".join(parts) if parts else "fetched certificate metadata") + f" from {cn_label}."
                request.session["homeglue_flash"] = {"title": "Auto-filled certificate info", "body": body}
            else:
                request.session["homeglue_flash"] = {
                    "title": "No public cert info found",
                    "body": f"We couldn't fetch certificate metadata from {cn_label}. If it's internal/unreachable, that's expected.",
                }
            return redirect("ui:sslcert_detail", sslcert_id=obj.id)
    else:
        init = {}
        cn = (request.GET.get("common_name") or "").strip()
        if cn:
            init["common_name"] = cn
        form = SSLCertificateForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("SSL Certificates", reverse("ui:sslcerts_list")), ("New", None)),
            "title": "New SSL certificate",
            "form": form,
            "submit_label": "Create",
            "submit_icon": "#i-plus",
            "primary_action": "create",
            "secondary_submit_buttons": [{"label": "Lookup", "name": "_action", "value": "lookup_public", "icon": "#i-bolt"}],
        },
    )


@login_required
def sslcert_detail(request: HttpRequest, sslcert_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    cert = get_object_or_404(SSLCertificate.objects.prefetch_related("domains"), id=sslcert_id, organization=org)
    can_admin = _is_org_admin(request.user, org)
    flash = request.session.pop("homeglue_flash", None)

    if request.method == "POST" and request.POST.get("_action") == "refresh_public":
        changed = False
        linked = 0
        info_found = False
        try:
            if (cert.common_name or "").strip():
                info = lookup_tls_certificate(cert.common_name)
                if info:
                    info_found = True
                    changed = bool(apply_ssl_public_info(obj=cert, info=info, force=True))
                    if changed:
                        cert.save()
                    for name in dns_names_for_cert(common_name=cert.common_name, info=info):
                        d, _ = Domain.objects.get_or_create(organization=org, name=name)
                        if not cert.domains.filter(id=d.id).exists():
                            cert.domains.add(d)
                            linked += 1
        except Exception:
            request.session["homeglue_flash"] = {"title": "Refresh failed", "body": "Unable to fetch certificate metadata right now."}
            return redirect("ui:sslcert_detail", sslcert_id=cert.id)
        if info_found:
            parts = []
            if changed:
                parts.append("updated fields")
            if linked:
                parts.append(f"linked {linked} domain(s)")
            request.session["homeglue_flash"] = (
                {"title": "Refreshed", "body": "Refresh completed (" + ", ".join(parts) + ")."} if parts else {"title": "Refreshed", "body": "Refresh completed."}
            )
        else:
            request.session["homeglue_flash"] = {
                "title": "No cert info found",
                "body": "We couldn't fetch certificate metadata from that common name.",
            }
        return redirect("ui:sslcert_detail", sslcert_id=cert.id)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=cert, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:sslcert_detail", sslcert_id=cert.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=cert)
        return redirect(request.get_full_path())

    if request.method == "POST":
        form = SSLCertificateForm(request.POST, instance=cert, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            # Best-effort: if user left public fields blank, fill them and link domains.
            info = None
            try:
                if (obj.common_name or "").strip():
                    info = lookup_tls_certificate(obj.common_name)
                    if info:
                        apply_ssl_public_info(obj=obj, info=info, force=False)
            except Exception:
                info = None
            obj.save()
            form.save_m2m()
            try:
                if info and (obj.common_name or "").strip():
                    for name in dns_names_for_cert(common_name=obj.common_name, info=info):
                        d, _ = Domain.objects.get_or_create(organization=org, name=name)
                        obj.domains.add(d)
            except Exception:
                pass
            return redirect("ui:sslcert_detail", sslcert_id=cert.id)
    else:
        form = SSLCertificateForm(instance=cert, org=org)

    edit_mode = _is_edit_mode(request)
    relationships = _relationships_for_object(org=org, obj=cert, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/sslcert_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("SSL Certificates", reverse("ui:sslcerts_list")), (cert.common_name or f"Cert {cert.id}", None)),
            "cert": cert,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:sslcert_detail", kwargs={"sslcert_id": cert.id}) + "?edit=1",
            "view_url": reverse("ui:sslcert_detail", kwargs={"sslcert_id": cert.id}),
            "can_admin": can_admin,
            "flash": flash,
            "expiry_badge": _expiry_badge(cert.not_after),
            "attachments": _attachments_for_object(org=org, obj=cert),
            "notes": _notes_for_object(org=org, obj=cert),
            "note_ref": _ref_for_obj(cert),
            "custom_fields": _custom_fields_for_model(org=org, model_cls=SSLCertificate),
            "custom_values": _custom_field_values_for_object(org=org, obj=cert),
            "activity": _activity_for_object(org=org, model_cls=SSLCertificate, obj_id=cert.id),
            "versions": _versions_for_object(org=org, obj=cert, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(cert)}",
        },
    )


@login_required
def sslcert_delete(request: HttpRequest, sslcert_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    cert = get_object_or_404(SSLCertificate, id=sslcert_id, organization=org)
    cancel = reverse("ui:sslcert_detail", kwargs={"sslcert_id": cert.id})
    redirect_url = reverse("ui:sslcerts_list")

    def _go():
        if cert.archived_at is None:
            cert.archived_at = timezone.now()
            cert.save(update_fields=["archived_at"])

    warning = "Relationships, notes, and attachments will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="SSL certificate",
        label=str(cert),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
def checklists_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)

    qs = Checklist.objects.filter(organization=org).annotate(item_count=Count("items")).order_by("-updated_at", "name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(description__icontains=q))
    items = list(qs[:200])
    return render(
        request,
        "ui/checklists_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklists", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "items": items,
            "new_url": reverse("ui:checklists_new"),
            "export_url": reverse("ui:checklists_export") + _qs_suffix(request),
            "bulk_url": reverse("ui:checklists_bulk"),
            "rel_counts": _relationship_counts_for_model(org=org, model_cls=Checklist, ids=[x.id for x in items]),
            "ref_prefix": _ref_prefix_for_model(Checklist),
            "tags_for_bulk": _tags_available_for_org(org)[:500],
        },
    )


@login_required
def checklists_export(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    qs = Checklist.objects.filter(organization=org).order_by("-updated_at", "name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(description__icontains=q))
    rows: list[list[str]] = []
    for c in list(qs[:5000]):
        tags = ";".join(sorted(list(c.tags.values_list("name", flat=True)))) if hasattr(c, "tags") else ""
        rows.append([str(c.name or ""), str(tags), str(c.updated_at.date() if c.updated_at else ""), str(c.description or "")])
    return _csv_http_response(
        filename=f"{org.name}-checklists.csv",
        header=["name", "tags", "updated", "description"],
        rows=rows,
    )


@login_required
def checklists_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = ChecklistForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            form.save_m2m()
            return redirect("ui:checklist_detail", checklist_id=obj.id)
    else:
        init = {}
        nm = (request.GET.get("name") or "").strip()
        if nm:
            init["name"] = nm
        form = ChecklistForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Checklists", reverse("ui:checklists_list")), ("New", None)), "title": "New checklist", "form": form},
    )


@login_required
def checklist_detail(request: HttpRequest, checklist_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    chk = get_object_or_404(Checklist, id=checklist_id, organization=org)
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=chk, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:checklist_detail", checklist_id=chk.id)

    if request.method == "POST" and request.POST.get("_action") == "add_item":
        txt = (request.POST.get("text") or "").strip()
        if txt:
            # Append at end.
            last = ChecklistItem.objects.filter(organization=org, checklist=chk).order_by("-sort_order", "-id").first()
            next_sort = int(last.sort_order + 1) if last else 1
            ChecklistItem.objects.create(organization=org, checklist=chk, text=txt[:400], sort_order=next_sort)
        return redirect("ui:checklist_detail", checklist_id=chk.id)

    if request.method == "POST" and request.POST.get("_action") == "toggle_item":
        iid = (request.POST.get("item_id") or "").strip()
        if iid.isdigit():
            it = ChecklistItem.objects.filter(organization=org, checklist=chk, id=int(iid)).first()
            if it:
                it.is_done = not bool(it.is_done)
                it.save(update_fields=["is_done", "updated_at"])
        return redirect("ui:checklist_detail", checklist_id=chk.id)

    if request.method == "POST" and request.POST.get("_action") == "delete_item":
        iid = (request.POST.get("item_id") or "").strip()
        if iid.isdigit():
            ChecklistItem.objects.filter(organization=org, checklist=chk, id=int(iid)).delete()
        return redirect("ui:checklist_detail", checklist_id=chk.id)

    if request.method == "POST":
        form = ChecklistForm(request.POST, instance=chk, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.save()
            form.save_m2m()
            return redirect("ui:checklist_detail", checklist_id=chk.id)
    else:
        form = ChecklistForm(instance=chk, org=org)

    items = list(ChecklistItem.objects.filter(organization=org, checklist=chk).order_by("sort_order", "id")[:1000])
    done = sum(1 for i in items if i.is_done)
    recent_runs = list(ChecklistRun.objects.filter(organization=org, checklist=chk, archived_at__isnull=True).order_by("-updated_at")[:10])

    relationships = _relationships_for_object(org=org, obj=chk, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/checklist_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklists", reverse("ui:checklists_list")), (chk.name, None)),
            "checklist": chk,
            "form": form,
            "can_admin": can_admin,
            "items": items,
            "done_count": done,
            "total_count": len(items),
            "recent_runs": recent_runs,
            "start_run_url": reverse("ui:checklist_run_start", kwargs={"checklist_id": chk.id}),
            "schedules_url": reverse("ui:checklist_schedules_list") + f"?checklist_id={chk.id}",
            "attachments": _attachments_for_object(org=org, obj=chk),
            "notes": _notes_for_object(org=org, obj=chk),
            "note_ref": _ref_for_obj(chk),
            "activity": _activity_for_object(org=org, model_cls=Checklist, obj_id=chk.id),
            "versions": _versions_for_object(org=org, obj=chk, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(chk)}",
        },
    )


@login_required
def checklist_schedules_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    q = (request.GET.get("q") or "").strip()
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    checklist_id = (request.GET.get("checklist_id") or "").strip()

    qs = ChecklistSchedule.objects.filter(organization=org).select_related("checklist", "assigned_to").order_by(
        "-enabled", "next_run_on", "name", "id"
    )
    qs = _filter_archived_qs(request, qs)
    if checklist_id.isdigit():
        qs = qs.filter(checklist_id=int(checklist_id))
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(checklist__name__icontains=q))

    items = list(qs[:200])
    new_url = reverse("ui:checklist_schedule_new")
    if checklist_id.isdigit():
        new_url += f"?checklist_id={int(checklist_id)}"

    return render(
        request,
        "ui/checklist_schedules_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklist Schedules", None)),
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "items": items,
            "new_url": new_url,
        },
    )


@login_required
def checklist_schedule_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    checklist = None
    cid = (request.GET.get("checklist_id") or "").strip()
    if cid.isdigit():
        checklist = Checklist.objects.filter(organization=org, archived_at__isnull=True, id=int(cid)).first()

    if request.method == "POST":
        form = ChecklistScheduleForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:checklist_schedule_detail", schedule_id=obj.id)
    else:
        init = {}
        if checklist:
            init["checklist"] = checklist
            init["name"] = checklist.name
        if init.get("next_run_on") is None:
            init["next_run_on"] = timezone.localdate()
        form = ChecklistScheduleForm(initial=init, org=org)

    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklist Schedules", reverse("ui:checklist_schedules_list")), ("New", None)),
            "title": "New checklist schedule",
            "form": form,
        },
    )


@login_required
def checklist_schedule_detail(request: HttpRequest, schedule_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)

    sched = get_object_or_404(ChecklistSchedule.objects.filter(organization=org).select_related("checklist", "assigned_to"), id=schedule_id)

    if request.method == "POST":
        form = ChecklistScheduleForm(request.POST, instance=sched, org=org)
        if form.is_valid():
            form.save()
            return redirect("ui:checklist_schedule_detail", schedule_id=sched.id)
    else:
        form = ChecklistScheduleForm(instance=sched, org=org)

    recent_runs = list(
        ChecklistRun.objects.filter(organization=org, schedule=sched, archived_at__isnull=True)
        .select_related("checklist", "assigned_to")
        .order_by("-created_at")[:10]
    )

    return render(
        request,
        "ui/checklist_schedule_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklist Schedules", reverse("ui:checklist_schedules_list")), (sched.name, None)),
            "schedule": sched,
            "form": form,
            "recent_runs": recent_runs,
            "delete_url": reverse("ui:checklist_schedule_delete", kwargs={"schedule_id": sched.id}),
        },
    )


@login_required
def checklist_schedule_delete(request: HttpRequest, schedule_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    sched = get_object_or_404(ChecklistSchedule, organization=org, id=schedule_id)
    cancel = reverse("ui:checklist_schedule_detail", kwargs={"schedule_id": sched.id})
    redirect_url = reverse("ui:checklist_schedules_list")

    def _go():
        if sched.archived_at is None:
            sched.archived_at = timezone.now()
            sched.enabled = False
            sched.save(update_fields=["archived_at", "enabled", "updated_at"])

    warning = "Existing runs will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="checklist schedule",
        label=str(sched),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived schedules will stop creating new runs.",
        on_confirm=_go,
    )


@login_required
def checklist_runs_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    q = (request.GET.get("q") or "").strip()
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    status = (request.GET.get("status") or "").strip().lower()

    qs = ChecklistRun.objects.filter(organization=org).select_related("checklist", "assigned_to", "created_by", "content_type").order_by("-updated_at", "-id")
    qs = _filter_archived_qs(request, qs)
    if status in {"open", "done", "canceled"}:
        qs = qs.filter(status=status)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(checklist__name__icontains=q))
    runs = list(qs[:200])

    # Compute completion counts (best-effort, bounded).
    run_ids = [int(r.id) for r in runs]
    counts = {}
    if run_ids:
        agg = (
            ChecklistRunItem.objects.filter(organization=org, run_id__in=run_ids)
            .values("run_id")
            .annotate(total=Count("id"), done=Count("id", filter=Q(is_done=True)))
        )
        for row in agg:
            counts[int(row["run_id"])] = {"total": int(row["total"] or 0), "done": int(row["done"] or 0)}

    return render(
        request,
        "ui/checklist_runs_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklist Runs", None)),
            "q": q,
            "status": status,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "runs": runs,
            "counts": counts,
            "new_url": reverse("ui:checklist_runs_new"),
        },
    )


def _copy_items_to_run(*, org, run: ChecklistRun, checklist: Checklist) -> int:
    from apps.checklists.services import copy_checklist_items_to_run

    return copy_checklist_items_to_run(org=org, run=run, checklist=checklist)


@login_required
def checklist_runs_new(request: HttpRequest) -> HttpResponse:
    """
    Create a run (optionally linked to a checklist and/or an object ref).
    """
    ctx = require_current_org(request)
    org = ctx.organization
    base_checklist = None
    cid = (request.GET.get("checklist_id") or "").strip()
    if cid.isdigit():
        base_checklist = Checklist.objects.filter(organization=org, id=int(cid)).first()

    if request.method == "POST":
        form = ChecklistRunForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.created_by = request.user
            if base_checklist:
                obj.checklist = base_checklist
                if not (obj.name or "").strip():
                    obj.name = base_checklist.name
            if obj.started_at is None:
                obj.started_at = timezone.now()
            obj.save()
            # Optional object link.
            ref = (form.cleaned_data.get("ref") or "").strip()
            if ref:
                parsed = _parse_ref(ref)
                if parsed:
                    ct, oid = parsed
                    obj.content_type = ct
                    obj.object_id = str(int(oid))
                    obj.save(update_fields=["content_type", "object_id"])
            if base_checklist:
                _copy_items_to_run(org=org, run=obj, checklist=base_checklist)
            return redirect("ui:checklist_run_detail", run_id=obj.id)
    else:
        init = {}
        if base_checklist:
            init["name"] = base_checklist.name
        ref = (request.GET.get("ref") or "").strip()
        if ref:
            init["ref"] = ref
        form = ChecklistRunForm(initial=init, org=org)

    return render(
        request,
        "ui/form.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklist Runs", reverse("ui:checklist_runs_list")), ("New", None)),
            "title": "New checklist run",
            "form": form,
        },
    )


@login_required
def checklist_run_start(request: HttpRequest, checklist_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    chk = get_object_or_404(Checklist, organization=org, id=checklist_id)
    qs = {"checklist_id": chk.id}
    ref = (request.GET.get("ref") or "").strip()
    if ref:
        qs["ref"] = ref
    return redirect(reverse("ui:checklist_runs_new") + "?" + urlencode(qs))


@login_required
def checklist_run_detail(request: HttpRequest, run_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    run = get_object_or_404(
        ChecklistRun.objects.filter(organization=org).select_related("checklist", "assigned_to", "created_by", "content_type"),
        id=run_id,
    )
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=run, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:checklist_run_detail", run_id=run.id)

    if request.method == "POST" and request.POST.get("_action") == "add_item":
        txt = (request.POST.get("text") or "").strip()
        if txt:
            last = ChecklistRunItem.objects.filter(organization=org, run=run).order_by("-sort_order", "-id").first()
            next_sort = int(last.sort_order + 1) if last else 1
            ChecklistRunItem.objects.create(organization=org, run=run, text=txt[:400], sort_order=next_sort)
        return redirect("ui:checklist_run_detail", run_id=run.id)

    if request.method == "POST" and request.POST.get("_action") == "toggle_item":
        iid = (request.POST.get("item_id") or "").strip()
        if iid.isdigit():
            it = ChecklistRunItem.objects.filter(organization=org, run=run, id=int(iid)).first()
            if it:
                it.set_done(done=not bool(it.is_done), user=request.user)
                it.save(update_fields=["is_done", "done_at", "done_by", "updated_at"])
        return redirect("ui:checklist_run_detail", run_id=run.id)

    if request.method == "POST" and request.POST.get("_action") == "delete_item":
        iid = (request.POST.get("item_id") or "").strip()
        if iid.isdigit():
            ChecklistRunItem.objects.filter(organization=org, run=run, id=int(iid)).delete()
        return redirect("ui:checklist_run_detail", run_id=run.id)

    if request.method == "POST" and request.POST.get("_action") == "mark_done":
        run.mark_done()
        run.save(update_fields=["status", "completed_at", "started_at", "updated_at"])
        return redirect("ui:checklist_run_detail", run_id=run.id)

    if request.method == "POST" and request.POST.get("_action") == "reopen":
        run.mark_open()
        run.save(update_fields=["status", "completed_at", "started_at", "updated_at"])
        return redirect("ui:checklist_run_detail", run_id=run.id)

    if request.method == "POST" and request.POST.get("_action") == "archive":
        if not can_admin and not getattr(request.user, "is_superuser", False):
            raise PermissionDenied("Org admin role required.")
        if run.archived_at is None:
            run.archived_at = timezone.now()
            run.save(update_fields=["archived_at"])
        return redirect("ui:checklist_runs_list")

    items = list(ChecklistRunItem.objects.filter(organization=org, run=run).order_by("sort_order", "id")[:2000])
    done = sum(1 for i in items if i.is_done)

    obj_link = None
    if run.content_type_id and run.object_id:
        obj_link = {"ref": f"{run.content_type.app_label}.{run.content_type.model}:{run.object_id}", "url": _ui_object_url(run.content_type.app_label, run.content_type.model, run.object_id)}

    relationships = _relationships_for_object(org=org, obj=run, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/checklist_run_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Checklist Runs", reverse("ui:checklist_runs_list")), (run.name, None)),
            "run": run,
            "can_admin": can_admin,
            "items": items,
            "done_count": done,
            "total_count": len(items),
            "object_link": obj_link,
            "attachments": _attachments_for_object(org=org, obj=run),
            "notes": _notes_for_object(org=org, obj=run),
            "note_ref": _ref_for_obj(run),
            "activity": _activity_for_object(org=org, model_cls=ChecklistRun, obj_id=run.id),
            "versions": _versions_for_object(org=org, obj=run, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(run)}",
        },
    )


@login_required
def checklist_delete(request: HttpRequest, checklist_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    chk = get_object_or_404(Checklist, id=checklist_id, organization=org)
    cancel = reverse("ui:checklist_detail", kwargs={"checklist_id": chk.id})
    redirect_url = reverse("ui:checklists_list")

    def _go():
        if chk.archived_at is None:
            chk.archived_at = timezone.now()
            chk.save(update_fields=["archived_at"])

    warning = "Items, relationships, notes, and attachments will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="checklist",
        label=str(chk),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
@require_POST
def checklists_bulk(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    return _bulk_action(
        request,
        org=org,
        model_cls=Checklist,
        base_qs=Checklist.objects.filter(organization=org),
        list_url_name="ui:checklists_list",
        supports_tags=True,
    )


@login_required
def flex_types_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    q = (request.GET.get("q") or "").strip()
    show_archived = (request.GET.get("archived") or "").strip() in {"1", "true", "yes", "on"}

    qs = FlexibleAssetType.objects.filter(organization=org).order_by("archived", "sort_order", "name")
    if not show_archived:
        qs = qs.filter(archived=False)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(description__icontains=q))

    return render(
        request,
        "ui/flex_types_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Flexible Assets", None)),
            "types": list(qs[:200]),
            "q": q,
            "show_archived": show_archived,
            "can_admin": can_admin,
            "new_url": reverse("ui:flex_type_new"),
        },
    )


@login_required
def flex_type_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    if request.method == "POST":
        form = FlexibleAssetTypeForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:flex_type_detail", type_id=obj.id)
    else:
        form = FlexibleAssetTypeForm(org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Flexible Assets", reverse("ui:flex_types_list")), ("New type", None)), "title": "New flexible asset type", "form": form},
    )


@login_required
def flex_type_detail(request: HttpRequest, type_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)

    form = None
    if can_admin:
        if request.method == "POST":
            form = FlexibleAssetTypeForm(request.POST, instance=ftype, org=org)
            if form.is_valid():
                form.save()
                return redirect("ui:flex_type_detail", type_id=ftype.id)
        else:
            form = FlexibleAssetTypeForm(instance=ftype, org=org)

    return render(
        request,
        "ui/flex_type_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Flexible Assets", reverse("ui:flex_types_list")), (ftype.name, None)),
            "type": ftype,
            "form": form,
            "can_admin": can_admin,
            "assets_url": reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}),
            "custom_fields_url": reverse("ui:custom_fields_list"),
        },
    )


@login_required
def flex_type_delete(request: HttpRequest, type_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    cancel = reverse("ui:flex_type_detail", kwargs={"type_id": ftype.id})
    redirect_url = reverse("ui:flex_types_list")

    def _go():
        ftype.delete()

    warning = "This will delete all flexible assets of this type."
    return _confirm_delete(
        request,
        org=org,
        kind="flexible asset type",
        label=str(ftype),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


@login_required
def flex_assets_list(request: HttpRequest, type_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    q = (request.GET.get("q") or "").strip()

    qs = FlexibleAsset.objects.filter(organization=org, asset_type=ftype).prefetch_related("tags").order_by("name")
    show_archived = _archived_mode(request) == "only"
    active_url, archived_url = _archived_toggle_urls(request)
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(notes__icontains=q))
    assets = list(qs[:200])
    rel_counts = _relationship_counts_for_model(org=org, model_cls=FlexibleAsset, ids=[int(a.id) for a in assets])

    return render(
        request,
        "ui/flex_assets_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Flexible Assets", reverse("ui:flex_types_list")), (ftype.name, None)),
            "type": ftype,
            "assets": assets,
            "q": q,
            "show_archived": show_archived,
            "active_url": active_url,
            "archived_url": archived_url,
            "can_admin": can_admin,
            "tags": _tags_available_for_org(org),
            "rel_counts": rel_counts,
            "new_url": reverse("ui:flex_asset_new", kwargs={"type_id": ftype.id}),
            "export_url": reverse("ui:flex_assets_export", kwargs={"type_id": ftype.id}) + _qs_suffix(request),
            "bulk_url": reverse("ui:flex_assets_bulk", kwargs={"type_id": ftype.id}),
        },
    )


@login_required
def flex_assets_export(request: HttpRequest, type_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    q = (request.GET.get("q") or "").strip()
    qs = FlexibleAsset.objects.filter(organization=org, asset_type=ftype).order_by("name")
    qs = _filter_archived_qs(request, qs)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(notes__icontains=q))

    header = ["name", "notes", "tags"]
    rows = []
    for a in qs[:5000]:
        rows.append([a.name or "", a.notes or "", ",".join([t.name for t in a.tags.all()])])
    return _csv_http_response(filename=f"{org.name}-{ftype.name}-flex-assets.csv", header=header, rows=rows)


@login_required
@require_POST
def flex_assets_bulk(request: HttpRequest, type_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    # `_bulk_action` redirects by list_url_name without args; handle delete/tag ourselves here.
    ids = [int(x) for x in request.POST.getlist("ids") if (x or "").isdigit()]
    action = (request.POST.get("action") or "").strip()
    if not ids:
        return _redirect_back(request, fallback_url=reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}))

    qs = FlexibleAsset.objects.filter(organization=org, asset_type=ftype, id__in=ids)

    if action in {"archive", "delete"}:
        _require_org_admin(request.user, org)
        now = timezone.now()
        for obj in list(qs):
            if getattr(obj, "archived_at", None) is None:
                obj.archived_at = now
                obj.save(update_fields=["archived_at"])
        return _redirect_back(request, fallback_url=reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}))

    if action == "tag_add":
        tag_id = request.POST.get("tag_id")
        tag_id = int(tag_id) if (tag_id or "").isdigit() else None
        if not tag_id:
            return _redirect_back(request, fallback_url=reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}))
        tag = _tags_available_for_org(org).filter(id=tag_id).first()
        if not tag:
            return _redirect_back(request, fallback_url=reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}))
        for obj in list(qs):
            obj.tags.add(tag)
        return _redirect_back(request, fallback_url=reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}))

    return _redirect_back(request, fallback_url=reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id}))


@login_required
def flex_asset_new(request: HttpRequest, type_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    if request.method == "POST":
        form = FlexibleAssetForm(request.POST, org=org, asset_type=ftype)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.asset_type = ftype
            obj.save()
            form.save_m2m()
            return redirect("ui:flex_asset_detail", type_id=ftype.id, asset_id=obj.id)
    else:
        form = FlexibleAssetForm(org=org, asset_type=ftype)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Flexible Assets", reverse("ui:flex_types_list")), (ftype.name, reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id})), ("New", None)), "title": f"New {ftype.name}", "form": form},
    )


@login_required
def flex_asset_detail(request: HttpRequest, type_id: int, asset_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    asset = get_object_or_404(FlexibleAsset, organization=org, asset_type=ftype, id=asset_id)
    can_admin = _is_org_admin(request.user, org)

    if request.method == "POST" and request.POST.get("_action") == "upload_attachment":
        _create_attachment(org=org, obj=asset, uploaded_by=request.user, file=request.FILES.get("file"))
        return redirect("ui:flex_asset_detail", type_id=ftype.id, asset_id=asset.id)

    if request.method == "POST" and request.POST.get("_action") == "save_custom_fields":
        _save_custom_fields_from_post(request=request, org=org, obj=asset)
        return redirect(request.get_full_path())

    if request.method == "POST":
        form = FlexibleAssetForm(request.POST, instance=asset, org=org, asset_type=ftype)
        if form.is_valid():
            form.save()
            return redirect("ui:flex_asset_detail", type_id=ftype.id, asset_id=asset.id)
    else:
        form = FlexibleAssetForm(instance=asset, org=org, asset_type=ftype)

    edit_mode = _is_edit_mode(request)
    relationships = _relationships_for_object(org=org, obj=asset, limit=50)
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/flex_asset_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Flexible Assets", reverse("ui:flex_types_list")), (ftype.name, reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id})), (asset.name, None)),
            "type": ftype,
            "asset": asset,
            "form": form,
            "edit_mode": edit_mode,
            "edit_url": reverse("ui:flex_asset_detail", kwargs={"type_id": ftype.id, "asset_id": asset.id}) + "?edit=1",
            "view_url": reverse("ui:flex_asset_detail", kwargs={"type_id": ftype.id, "asset_id": asset.id}),
            "can_admin": can_admin,
            "attachments": _attachments_for_object(org=org, obj=asset),
            "notes": _notes_for_object(org=org, obj=asset),
            "note_ref": _ref_for_obj(asset),
            "custom_fields": _custom_fields_for_flex_asset(org=org, asset_type=ftype),
            "custom_values": _custom_field_values_for_object(org=org, obj=asset),
            "activity": _activity_for_object(org=org, model_cls=FlexibleAsset, obj_id=asset.id),
            "versions": _versions_for_object(org=org, obj=asset, limit=20),
            "can_restore": _is_org_admin(request.user, org),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(asset)}",
        },
    )


@login_required
def flex_asset_delete(request: HttpRequest, type_id: int, asset_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    ftype = get_object_or_404(FlexibleAssetType, organization=org, id=type_id)
    asset = get_object_or_404(FlexibleAsset, organization=org, asset_type=ftype, id=asset_id)
    cancel = reverse("ui:flex_asset_detail", kwargs={"type_id": ftype.id, "asset_id": asset.id})
    redirect_url = reverse("ui:flex_assets_list", kwargs={"type_id": ftype.id})

    def _go():
        if asset.archived_at is None:
            asset.archived_at = timezone.now()
            asset.save(update_fields=["archived_at"])

    warning = "Relationships, notes, and attachments will remain. This is reversible."
    return _confirm_delete(
        request,
        org=org,
        kind="flexible asset",
        label=str(asset),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        verb="Archive",
        sub="Archived items are hidden from normal lists but can be restored later.",
        on_confirm=_go,
    )


@login_required
def relationships_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    filter_ref = (request.GET.get("ref") or "").strip()
    filter_label = None
    filter_invalid = False
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)
    qs = (
        Relationship.objects.filter(organization=org)
        .select_related("relationship_type", "source_content_type", "target_content_type", "created_by")
        .order_by("-created_at")
    )

    if filter_ref:
        parsed = _parse_ref(filter_ref)
        if not parsed:
            filter_invalid = True
        else:
            ct, oid = parsed
            qs = qs.filter(
                (Q(source_content_type=ct) & Q(source_object_id=oid))
                | (Q(target_content_type=ct) & Q(target_object_id=oid))
            )

            # Best-effort label for the filter chip.
            try:
                model_cls = ct.model_class()
                obj = None
                if model_cls:
                    if hasattr(model_cls, "organization_id"):
                        obj = model_cls.objects.filter(organization=org, id=int(oid)).first()
                    else:
                        obj = model_cls.objects.filter(id=int(oid)).first()
                if obj and model_cls is Document and not can_admin and not _can_view_document(user=request.user, org=org, doc=obj):
                    filter_label = _human_ref_label(ct=ct, restricted=True)
                elif obj and model_cls is PasswordEntry and not can_admin and not _can_view_password(user=request.user, org=org, entry=obj):
                    filter_label = _human_ref_label(ct=ct, restricted=True)
                elif obj:
                    filter_label = _human_ref_label(ct=ct, obj=obj)
                else:
                    filter_label = _human_ref_label(ct=ct, oid=oid)
            except Exception:
                filter_label = filter_ref

    relationships = list(qs[:200])
    relationships_view = _relationships_view(request=request, org=org, relationships=relationships)
    return render(
        request,
        "ui/relationships_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Relationships", None)),
            "relationships": relationships,
            "relationships_view": relationships_view,
            "relationships_new_url": reverse("ui:relationships_new"),
            "filter_ref": filter_ref,
            "filter_label": filter_label,
            "filter_invalid": filter_invalid,
        },
    )


@login_required
def relationships_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    if request.method == "POST":
        form = RelationshipForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.created_by = request.user
            obj.save()
            return redirect("ui:relationships_list")
    else:
        init = {}
        src = (request.GET.get("source_ref") or "").strip()
        tgt = (request.GET.get("target_ref") or "").strip()
        if src:
            init["source_ref"] = src
        if tgt:
            init["target_ref"] = tgt
        form = RelationshipForm(initial=init, org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Relationships", reverse("ui:relationships_list")), ("New", None)), "title": "New relationship", "form": form},
    )


@login_required
def notes_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    filter_ref = (request.GET.get("ref") or "").strip()
    filter_label = None
    filter_invalid = False

    qs = Note.objects.filter(organization=org).select_related("created_by", "content_type").order_by("-created_at")
    can_admin = _is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False)

    if filter_ref:
        parsed = _parse_ref(filter_ref)
        if not parsed:
            filter_invalid = True
        else:
            ct, oid = parsed
            qs = qs.filter(content_type=ct, object_id=oid)

            # Best-effort label for the filter chip.
            try:
                model_cls = ct.model_class()
                obj = None
                if model_cls:
                    if hasattr(model_cls, "organization_id"):
                        obj = model_cls.objects.filter(organization=org, id=int(oid)).first()
                    else:
                        obj = model_cls.objects.filter(id=int(oid)).first()
                if obj and model_cls is Document and not can_admin and not _can_view_document(user=request.user, org=org, doc=obj):
                    filter_label = _human_ref_label(ct=ct, restricted=True)
                elif obj and model_cls is PasswordEntry and not can_admin and not _can_view_password(user=request.user, org=org, entry=obj):
                    filter_label = _human_ref_label(ct=ct, restricted=True)
                else:
                    filter_label = _human_ref_label(ct=ct, obj=obj) if obj else _human_ref_label(ct=ct, oid=oid)
            except Exception:
                filter_label = filter_ref

    # Hide notes attached to restricted docs/passwords for non-admins.
    if not can_admin:
        doc_ct = ContentType.objects.get_for_model(Document)
        pw_ct = ContentType.objects.get_for_model(PasswordEntry)
        doc_ids = list(
            Document.objects.filter(organization=org).filter(_visible_docs_q(request.user, org)).values_list("id", flat=True)[:5000]
        )
        pw_ids = list(
            PasswordEntry.objects.filter(organization=org).filter(_visible_passwords_q(request.user, org)).values_list("id", flat=True)[:5000]
        )
        qs = qs.exclude(Q(content_type=doc_ct) & ~Q(object_id__in=[str(i) for i in doc_ids]))
        qs = qs.exclude(Q(content_type=pw_ct) & ~Q(object_id__in=[str(i) for i in pw_ids]))

    return render(
        request,
        "ui/notes_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Notes", None)),
            "notes": list(qs[:200]),
            "filter_ref": filter_ref,
            "filter_label": filter_label,
            "filter_invalid": filter_invalid,
        },
    )


@login_required
@require_POST
def notes_add(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    title = (request.POST.get("title") or "").strip()
    body = (request.POST.get("body") or "").strip()
    ref = (request.POST.get("ref") or "").strip()

    ct = None
    oid = None
    if ref:
        parsed = _parse_ref(ref)
        if not parsed:
            raise PermissionDenied("Invalid ref.")
        ct, oid = parsed

        # Prevent cross-org refs when objects are org-scoped.
        model_cls = ct.model_class()
        if model_cls is not None:
            if hasattr(model_cls, "organization_id"):
                ok = model_cls.objects.filter(organization=org, id=int(oid)).exists()
            else:
                ok = model_cls.objects.filter(id=int(oid)).exists()
            if not ok:
                raise PermissionDenied("Referenced object not found in current organization.")

    if title or body:
        Note.objects.create(
            organization=org,
            title=title,
            body=body,
            created_by=request.user if request.user.is_authenticated else None,
            content_type=ct,
            object_id=oid,
        )

    return _redirect_back(request, fallback_url=reverse("ui:notes_list"))


@login_required
@require_POST
def note_delete(request: HttpRequest, note_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    note = get_object_or_404(Note, organization=org, id=note_id)

    if not (_is_org_admin(request.user, org) or getattr(request.user, "is_superuser", False) or note.created_by_id == request.user.id):
        raise PermissionDenied("Not allowed to delete this note.")

    note.delete()
    return _redirect_back(request, fallback_url=reverse("ui:notes_list"))


@login_required
def integrations_list(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    proxmox = list(ProxmoxConnection.objects.filter(organization=org).order_by("name"))
    return render(
        request,
        "ui/integrations_list.html",
        {
            "org": org,
            "crumbs": _crumbs(("Integrations", None)),
            "proxmox": proxmox,
            "proxmox_new_url": reverse("ui:proxmox_new"),
            "can_admin": can_admin,
        },
    )


@login_required
def proxmox_new(request: HttpRequest) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    if request.method == "POST":
        form = ProxmoxConnectionForm(request.POST, org=org)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.organization = org
            obj.save()
            return redirect("ui:proxmox_detail", conn_id=obj.id)
    else:
        form = ProxmoxConnectionForm(org=org)
    return render(
        request,
        "ui/form.html",
        {"org": org, "crumbs": _crumbs(("Integrations", reverse("ui:integrations_list")), ("New Proxmox", None)), "title": "New Proxmox connection", "form": form},
    )


@login_required
def proxmox_detail(request: HttpRequest, conn_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    can_admin = _is_org_admin(request.user, org)
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)

    form = None
    if can_admin:
        if request.method == "POST" and request.POST.get("_action") == "save":
            form = ProxmoxConnectionForm(request.POST, instance=conn, org=org)
            if form.is_valid():
                form.save()
                return redirect("ui:proxmox_detail", conn_id=conn.id)
        else:
            form = ProxmoxConnectionForm(instance=conn, org=org)

    nodes = list(ProxmoxNode.objects.filter(connection=conn).select_related("asset", "config_item").order_by("node")[:200])
    guests = list(ProxmoxGuest.objects.filter(connection=conn).select_related("asset", "config_item").order_by("guest_type", "vmid")[:500])
    nets = list(ProxmoxNetwork.objects.filter(connection=conn).order_by("node", "iface")[:500])
    stor = list(conn.storages.order_by("node", "storage")[:200])
    pools = list(conn.pools.order_by("poolid")[:50])
    vnets = list(conn.sdn_vnets.order_by("vnet")[:50])

    return render(
        request,
        "ui/proxmox_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(("Integrations", reverse("ui:integrations_list")), (conn.name, None)),
            "conn": conn,
            "form": form,
            "can_admin": can_admin,
            "nodes": nodes,
            "guests": guests,
            "networks": nets,
            "storages": stor,
            "pools": pools,
            "vnets": vnets,
            "guests_url": reverse("ui:proxmox_guests", kwargs={"conn_id": conn.id}),
            "nodes_url": reverse("ui:proxmox_nodes", kwargs={"conn_id": conn.id}),
        },
    )


@login_required
@require_POST
def proxmox_sync(request: HttpRequest, conn_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)
    res = sync_proxmox_connection(conn)
    if res.ok:
        request.session["homeglue_flash"] = {
            "title": "Proxmox synced",
            "body": f"Sync completed: {res.nodes} nodes, {res.guests} guests, {res.networks} networks.",
        }
    else:
        request.session["homeglue_flash"] = {
            "title": "Proxmox sync failed",
            "body": res.error or "Unknown error.",
        }
    return redirect("ui:proxmox_detail", conn_id=conn.id)


@login_required
def proxmox_delete(request: HttpRequest, conn_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    _require_org_admin(request.user, org)
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)
    cancel = reverse("ui:proxmox_detail", kwargs={"conn_id": conn.id})
    redirect_url = reverse("ui:integrations_list")

    def _go():
        conn.delete()

    warning = "This will delete the stored Proxmox inventory snapshots for this connection."
    return _confirm_delete(
        request,
        org=org,
        kind="Proxmox connection",
        label=str(conn),
        cancel_url=cancel,
        redirect_url=redirect_url,
        warning=warning,
        on_confirm=_go,
    )


def _paginate(*, request: HttpRequest, qs, per_page: int = 100):
    per_page = int(per_page) if str(per_page).isdigit() else 100
    per_page = max(10, min(200, per_page))
    page_raw = (request.GET.get("page") or "1").strip()
    page = int(page_raw) if page_raw.isdigit() else 1
    page = max(1, page)
    total = qs.count()
    offset = (page - 1) * per_page
    items = list(qs[offset : offset + per_page])
    has_prev = page > 1
    has_next = (offset + per_page) < total
    return {"items": items, "page": page, "per_page": per_page, "total": total, "has_prev": has_prev, "has_next": has_next}


@login_required
def proxmox_guests(request: HttpRequest, conn_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)

    q = (request.GET.get("q") or "").strip()
    status = (request.GET.get("status") or "").strip()
    gtype = (request.GET.get("type") or "").strip()
    node = (request.GET.get("node") or "").strip()
    has_ip = (request.GET.get("has_ip") or "").strip()
    pool = (request.GET.get("pool") or "").strip()

    qs = ProxmoxGuest.objects.filter(connection=conn).select_related("asset", "config_item").order_by("node", "guest_type", "vmid")
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(node__icontains=q) | Q(vmid__icontains=q))
    if status in {"running", "stopped"}:
        qs = qs.filter(status=status)
    if gtype in {ProxmoxGuest.TYPE_QEMU, ProxmoxGuest.TYPE_LXC}:
        qs = qs.filter(guest_type=gtype)
    if node:
        qs = qs.filter(node=node)
    if pool:
        qs = qs.filter(pool=pool)
    if has_ip in {"1", "true", "yes"}:
        qs = qs.exclude(ip_addrs=[])

    node_choices = list(ProxmoxGuest.objects.filter(connection=conn).exclude(node="").values_list("node", flat=True).distinct().order_by("node")[:200])
    pool_choices = list(ProxmoxGuest.objects.filter(connection=conn).exclude(pool="").values_list("pool", flat=True).distinct().order_by("pool")[:200])
    counts = {
        "guests": ProxmoxGuest.objects.filter(connection=conn).count(),
        "running": ProxmoxGuest.objects.filter(connection=conn, status="running").count(),
        "stopped": ProxmoxGuest.objects.filter(connection=conn, status="stopped").count(),
    }
    page = _paginate(request=request, qs=qs, per_page=100)

    return render(
        request,
        "ui/proxmox_guests.html",
        {
            "org": org,
            "crumbs": _crumbs(("Integrations", reverse("ui:integrations_list")), (conn.name, reverse("ui:proxmox_detail", kwargs={"conn_id": conn.id})), ("Guests", None)),
            "conn": conn,
            "q": q,
            "status": status,
            "type": gtype,
            "node": node,
            "has_ip": has_ip,
            "pool": pool,
            "node_choices": node_choices,
            "pool_choices": pool_choices,
            "counts": counts,
            "guests": page["items"],
            "page": page,
        },
    )


@login_required
def proxmox_guest_detail(request: HttpRequest, conn_id: int, guest_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)
    guest = get_object_or_404(ProxmoxGuest.objects.select_related("asset", "config_item"), connection=conn, id=guest_id)

    return render(
        request,
        "ui/proxmox_guest_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(
                ("Integrations", reverse("ui:integrations_list")),
                (conn.name, reverse("ui:proxmox_detail", kwargs={"conn_id": conn.id})),
                ("Guests", reverse("ui:proxmox_guests", kwargs={"conn_id": conn.id})),
                (guest.name or f"{guest.guest_type} {guest.vmid}", None),
            ),
            "conn": conn,
            "guest": guest,
            "ip_history": list(guest.ip_history.order_by("-last_seen_at")[:200]),
            "relationships": _relationships_for_object(org=org, obj=guest, limit=50),
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(guest)}",
            "attachments": _attachments_for_object(org=org, obj=guest),
            "notes": _notes_for_object(org=org, obj=guest),
            "note_ref": _ref_for_obj(guest),
        },
    )


@login_required
def proxmox_nodes(request: HttpRequest, conn_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)
    q = (request.GET.get("q") or "").strip()

    qs = ProxmoxNode.objects.filter(connection=conn).select_related("asset", "config_item").order_by("node")
    if q:
        qs = qs.filter(node__icontains=q)

    page = _paginate(request=request, qs=qs, per_page=100)
    return render(
        request,
        "ui/proxmox_nodes.html",
        {
            "org": org,
            "crumbs": _crumbs(("Integrations", reverse("ui:integrations_list")), (conn.name, reverse("ui:proxmox_detail", kwargs={"conn_id": conn.id})), ("Nodes", None)),
            "conn": conn,
            "q": q,
            "nodes": page["items"],
            "page": page,
        },
    )


@login_required
def proxmox_node_detail(request: HttpRequest, conn_id: int, node_id: int) -> HttpResponse:
    ctx = require_current_org(request)
    org = ctx.organization
    conn = get_object_or_404(ProxmoxConnection, organization=org, id=conn_id)
    node = get_object_or_404(ProxmoxNode.objects.select_related("asset", "config_item"), connection=conn, id=node_id)
    networks = list(ProxmoxNetwork.objects.filter(connection=conn, node=node.node).order_by("iface")[:500])
    storages = list(conn.storages.filter(node=node.node).order_by("storage")[:200])
    guests = list(
        ProxmoxGuest.objects.filter(connection=conn, node=node.node)
        .select_related("asset", "config_item")
        .order_by("guest_type", "vmid")[:500]
    )

    return render(
        request,
        "ui/proxmox_node_detail.html",
        {
            "org": org,
            "crumbs": _crumbs(
                ("Integrations", reverse("ui:integrations_list")),
                (conn.name, reverse("ui:proxmox_detail", kwargs={"conn_id": conn.id})),
                ("Nodes", reverse("ui:proxmox_nodes", kwargs={"conn_id": conn.id})),
                (node.node, None),
            ),
            "conn": conn,
            "node": node,
            "networks": networks,
            "storages": storages,
            "guests": guests,
            "relationships": _relationships_for_object(org=org, obj=node, limit=50),
            "add_relationship_url": reverse("ui:relationships_new") + f"?source_ref={_ref_for_obj(node)}",
            "attachments": _attachments_for_object(org=org, obj=node),
            "notes": _notes_for_object(org=org, obj=node),
            "note_ref": _ref_for_obj(node),
        },
    )
