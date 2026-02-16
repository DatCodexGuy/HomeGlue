from __future__ import annotations

import json
import re
import tempfile
import zipfile
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from django.core.files import File
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.core.serializers import serialize
from django.db.models import Q
from django.utils import timezone

from apps.assets.models import Asset, ConfigurationItem
from apps.backups.models import BackupPolicy, BackupSnapshot
from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem, ChecklistSchedule
from apps.core.models import (
    Attachment,
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
)
from apps.docsapp.models import Document, DocumentFolder, DocumentTemplate
from apps.flexassets.models import FlexibleAsset, FlexibleAssetType
from apps.integrations.models import ProxmoxConnection
from apps.integrations.models import (
    ProxmoxCluster,
    ProxmoxGuest,
    ProxmoxGuestIP,
    ProxmoxNetwork,
    ProxmoxNode,
    ProxmoxPool,
    ProxmoxSdnSubnet,
    ProxmoxSdnVnet,
    ProxmoxSdnZone,
    ProxmoxStorage,
)
from apps.netapp.models import Domain, SSLCertificate
from apps.people.models import Contact
from apps.secretsapp.models import PasswordEntry, PasswordFolder, PasswordShareLink
from apps.versionsapp.models import ObjectVersion
from apps.audit.models import AuditEvent
from apps.workflows.models import Notification, NotificationDeliveryAttempt, WebhookEndpoint, WorkflowRule


def _safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "org"


def _serialize_qs(qs) -> list[dict]:
    if qs is None:
        return []
    data = serialize("json", qs, use_natural_foreign_keys=True)
    try:
        return json.loads(data)
    except Exception:
        return []


class Command(BaseCommand):
    help = "Process pending org backup snapshots (build zip bundles into media storage)."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")
        parser.add_argument("--limit", type=int, default=1, help="Max snapshots to process per run.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        limit = int(opts.get("limit") or 1)

        qs = BackupSnapshot.objects.select_related("organization").filter(status=BackupSnapshot.STATUS_PENDING).order_by("created_at")
        if org_id:
            qs = qs.filter(organization_id=int(org_id))

        for snap in list(qs[: max(1, limit)]):
            self._process_snapshot(snap)

    def _process_snapshot(self, snap: BackupSnapshot) -> None:
        org = snap.organization
        snap.status = BackupSnapshot.STATUS_RUNNING
        snap.started_at = timezone.now()
        snap.error = ""
        snap.save(update_fields=["status", "started_at", "error"])

        ts = datetime.now(dt_timezone.utc).strftime("%Y%m%d-%H%M%S")
        base_name = f"homeglue-{_safe_slug(org.name)}-{ts}.zip"
        snap.filename = base_name
        snap.save(update_fields=["filename"])

        try:
            fixture_objects: list[dict] = []

            # Core identity/org
            fixture_objects += _serialize_qs(Organization.objects.filter(id=org.id))
            fixture_objects += _serialize_qs(OrganizationMembership.objects.filter(organization=org))
            try:
                User = get_user_model()
                member_ids = list(OrganizationMembership.objects.filter(organization=org).values_list("user_id", flat=True))
                fixture_objects += _serialize_qs(User.objects.filter(id__in=member_ids))
            except Exception:
                pass

            # Core content
            fixture_objects += _serialize_qs(Location.objects.filter(organization=org))
            fixture_objects += _serialize_qs(Tag.objects.filter(Q(organization__isnull=True) | Q(organization=org)))
            fixture_objects += _serialize_qs(RelationshipType.objects.filter(organization=org))
            fixture_objects += _serialize_qs(Relationship.objects.filter(organization=org))
            fixture_objects += _serialize_qs(CustomField.objects.filter(organization=org))
            fixture_objects += _serialize_qs(CustomFieldValue.objects.filter(organization=org))
            fixture_objects += _serialize_qs(Note.objects.filter(organization=org))
            fixture_objects += _serialize_qs(SavedView.objects.filter(organization=org))
            fixture_objects += _serialize_qs(BackupPolicy.objects.filter(organization=org))

            # Inventory
            fixture_objects += _serialize_qs(Contact.objects.filter(organization=org))
            fixture_objects += _serialize_qs(Asset.objects.filter(organization=org))
            fixture_objects += _serialize_qs(ConfigurationItem.objects.filter(organization=org))
            fixture_objects += _serialize_qs(FlexibleAssetType.objects.filter(organization=org))
            fixture_objects += _serialize_qs(FlexibleAsset.objects.filter(organization=org))

            # Docs
            fixture_objects += _serialize_qs(DocumentFolder.objects.filter(organization=org))
            fixture_objects += _serialize_qs(DocumentTemplate.objects.filter(organization=org))
            fixture_objects += _serialize_qs(Document.objects.filter(organization=org))

            # Secrets
            fixture_objects += _serialize_qs(PasswordFolder.objects.filter(organization=org))
            fixture_objects += _serialize_qs(PasswordEntry.objects.filter(organization=org))
            fixture_objects += _serialize_qs(PasswordShareLink.objects.filter(organization=org))

            # Domains / SSL
            fixture_objects += _serialize_qs(Domain.objects.filter(organization=org))
            fixture_objects += _serialize_qs(SSLCertificate.objects.filter(organization=org))

            # Checklists
            fixture_objects += _serialize_qs(Checklist.objects.filter(organization=org))
            fixture_objects += _serialize_qs(ChecklistItem.objects.filter(organization=org))
            fixture_objects += _serialize_qs(ChecklistRun.objects.filter(organization=org))
            fixture_objects += _serialize_qs(ChecklistRunItem.objects.filter(organization=org))
            fixture_objects += _serialize_qs(ChecklistSchedule.objects.filter(organization=org))

            # Workflows
            fixture_objects += _serialize_qs(WorkflowRule.objects.filter(organization=org))
            fixture_objects += _serialize_qs(WebhookEndpoint.objects.filter(organization=org))
            fixture_objects += _serialize_qs(Notification.objects.filter(organization=org))
            fixture_objects += _serialize_qs(NotificationDeliveryAttempt.objects.filter(notification__organization=org))

            # Versions
            fixture_objects += _serialize_qs(ObjectVersion.objects.filter(organization=org))

            # Audit
            fixture_objects += _serialize_qs(AuditEvent.objects.filter(organization=org))

            # Integrations
            fixture_objects += _serialize_qs(ProxmoxConnection.objects.filter(organization=org))
            fixture_objects += _serialize_qs(ProxmoxNode.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxGuest.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxNetwork.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxCluster.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxStorage.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxGuestIP.objects.filter(guest__connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxPool.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxSdnZone.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxSdnVnet.objects.filter(connection__organization=org))
            fixture_objects += _serialize_qs(ProxmoxSdnSubnet.objects.filter(connection__organization=org))

            # Attachments + underlying media files
            attachments = list(Attachment.objects.filter(organization=org).select_related("content_type")[:20000])
            fixture_objects += _serialize_qs(Attachment.objects.filter(organization=org))

            manifest = {
                "homeglue_backup_version": 2,
                "created_at": timezone.now().isoformat(),
                "organization_id": org.id,
                "organization_name": org.name,
                "counts": {
                    "fixture_objects": len(fixture_objects),
                    "attachments": len(attachments),
                },
                "notes": "Restore is still manual. Recommended: restore into a fresh HomeGlue stack (empty DB + media) then load fixture.json with Django loaddata.",
            }

            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                fixture_path = td_path / "fixture.json"
                manifest_path = td_path / "manifest.json"
                fixture_path.write_text(json.dumps(fixture_objects, indent=2, sort_keys=True), encoding="utf-8")
                manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

                zip_path = td_path / base_name
                with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                    z.write(str(manifest_path), arcname="manifest.json")
                    z.write(str(fixture_path), arcname="fixture.json")

                    for a in attachments:
                        try:
                            if not a.file:
                                continue
                            name = getattr(a.file, "name", "") or ""
                            if not name:
                                continue
                            arc = f"media/{name}"
                            # Stream into the zip to avoid reading entire files into memory.
                            with z.open(arc, "w") as dest:
                                with a.file.open("rb") as src:
                                    while True:
                                        chunk = src.read(1024 * 256)
                                        if not chunk:
                                            break
                                        dest.write(chunk)
                        except Exception:
                            continue

                with open(zip_path, "rb") as fh:
                    snap.file.save(base_name, File(fh), save=False)
                try:
                    snap.bytes = int(zip_path.stat().st_size)
                except Exception:
                    snap.bytes = None

            snap.status = BackupSnapshot.STATUS_SUCCESS
            snap.finished_at = timezone.now()
            snap.save(update_fields=["status", "finished_at", "file", "bytes"])
        except Exception as e:
            snap.status = BackupSnapshot.STATUS_FAILED
            snap.finished_at = timezone.now()
            snap.error = str(e)
            snap.save(update_fields=["status", "finished_at", "error"])
