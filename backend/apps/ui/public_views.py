from __future__ import annotations

import mimetypes
from pathlib import Path

from django.db import transaction
from django.http import FileResponse
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from apps.audit.models import AuditEvent
from apps.core.models import AttachmentShareLink
from apps.secretsapp.models import PasswordShareLink


@require_http_methods(["GET", "POST"])
def password_share(request: HttpRequest, token: str) -> HttpResponse:
    """
    Public password share link (no auth). Token is looked up via SHA256 hash.

    We deliberately do not support "view-only without reveal": the reveal is a POST to
    avoid accidental browser prefetch / caching patterns.
    """

    token_hash = PasswordShareLink.hash_token(token or "")
    share = PasswordShareLink.objects.select_related("password_entry", "organization").filter(token_hash=token_hash).first()
    if not share:
        raise Http404("Share not found.")

    entry = share.password_entry
    org = share.organization
    password = None
    reveal_attempted = False

    active = share.is_active()
    if request.method == "POST" and (request.POST.get("_action") or "") == "reveal":
        reveal_attempted = True
        if active:
            with transaction.atomic():
                s = (
                    PasswordShareLink.objects.select_for_update()
                    .select_related("password_entry", "organization")
                    .get(id=share.id)
                )
                if not s.is_active():
                    share = s
                    active = False
                else:
                    now = timezone.now()
                    s.view_count = int(s.view_count or 0) + 1
                    s.last_viewed_at = now
                    if s.one_time and not s.consumed_at:
                        s.consumed_at = now
                    s.save(update_fields=["view_count", "last_viewed_at", "consumed_at"])
                    share = s
                    active = share.is_active()
                    password = s.password_entry.get_password()

    resp = render(
        request,
        "ui/share_password.html",
        {
            "share": share,
            "entry": entry,
            "org": None,  # avoid any "current org" assumptions in base.html
            "active": active,
            "password": password,
            "reveal_attempted": reveal_attempted,
            "now": timezone.now(),
        },
    )
    # Avoid caching and leaking tokens via referer headers.
    resp["Cache-Control"] = "no-store"
    resp["Pragma"] = "no-cache"
    resp["Referrer-Policy"] = "no-referrer"
    return resp


@require_http_methods(["GET", "POST"])
def file_share(request: HttpRequest, token: str) -> HttpResponse:
    """
    Public file share link (no auth). Token is looked up via SHA256 hash.
    Download requires explicit POST to reduce accidental prefetch and leakage.
    """

    token_hash = AttachmentShareLink.hash_token(token or "")
    share = AttachmentShareLink.objects.select_related("attachment", "organization").filter(token_hash=token_hash).first()
    if not share:
        raise Http404("Share not found.")

    a = share.attachment
    filename = a.filename or (Path(getattr(a.file, "name", "")).name if a.file else f"attachment-{a.id}")
    active = share.is_active()
    download_attempted = False
    should_download = False

    if request.method == "POST" and (request.POST.get("_action") or "") == "download":
        download_attempted = True
        if active:
            with transaction.atomic():
                s = (
                    AttachmentShareLink.objects.select_for_update()
                    .select_related("attachment", "organization")
                    .get(id=share.id)
                )
                if not s.is_active():
                    share = s
                    active = False
                else:
                    now = timezone.now()
                    s.view_count = int(s.view_count or 0) + 1
                    s.last_viewed_at = now
                    if s.one_time and not s.consumed_at:
                        s.consumed_at = now
                    s.save(update_fields=["view_count", "last_viewed_at", "consumed_at"])
                    share = s
                    active = share.is_active()
                    should_download = True

            if should_download and share:
                try:
                    f = share.attachment.file.open("rb")
                except Exception:
                    raise Http404("File unavailable.")
                try:
                    AuditEvent.objects.create(
                        organization=share.organization,
                        user=None,
                        ip=(request.META.get("REMOTE_ADDR") or "")[:64] or None,
                        action=AuditEvent.ACTION_UPDATE,
                        model="core.Attachment",
                        object_pk=str(share.attachment_id),
                        summary=f"File SafeShare download via public link #{share.id}.",
                    )
                except Exception:
                    pass
                ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                resp = FileResponse(f, as_attachment=True, filename=Path(filename).name, content_type=ctype)
                resp["Cache-Control"] = "no-store"
                resp["Pragma"] = "no-cache"
                resp["Referrer-Policy"] = "no-referrer"
                return resp

    resp = render(
        request,
        "ui/share_file.html",
        {
            "share": share,
            "org": None,
            "active": active,
            "filename": filename,
            "download_attempted": download_attempted,
            "now": timezone.now(),
        },
    )
    resp["Cache-Control"] = "no-store"
    resp["Pragma"] = "no-cache"
    resp["Referrer-Policy"] = "no-referrer"
    return resp
