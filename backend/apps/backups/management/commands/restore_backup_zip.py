from __future__ import annotations

import json
import zipfile
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command

from apps.backups.models import BackupRestoreBundle


def _safe_extract_media(*, z: zipfile.ZipFile, media_root: Path) -> int:
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
        # Directories
        if name.endswith("/"):
            continue

        rel = name[len("media/") :]
        rel = rel.lstrip("/").replace("\\", "/")
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


class Command(BaseCommand):
    help = "Guided restore helper for HomeGlue backup zips (extract media and/or run loaddata)."

    def add_arguments(self, parser):
        parser.add_argument("--zip", dest="zip_path", default=None, help="Path to a backup zip accessible inside the container.")
        parser.add_argument("--bundle-id", type=int, default=None, help="BackupRestoreBundle id to restore (uses its uploaded file).")
        parser.add_argument("--extract-media", action="store_true", help="Extract media/ into MEDIA_ROOT.")
        parser.add_argument("--loaddata", action="store_true", help="Run Django loaddata on fixture.json from the zip.")
        parser.add_argument("--media-root", default=None, help="Override MEDIA_ROOT (default: settings.MEDIA_ROOT).")
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Required when using --loaddata (acknowledges this can overwrite/duplicate data if DB isn't empty).",
        )

    def handle(self, *args, **opts):
        zip_path = (opts.get("zip_path") or "").strip()
        bundle_id = opts.get("bundle_id")
        do_extract = bool(opts.get("extract_media"))
        do_loaddata = bool(opts.get("loaddata"))
        apply = bool(opts.get("apply"))

        if bundle_id:
            b = BackupRestoreBundle.objects.filter(id=int(bundle_id)).first()
            if not b or not b.file:
                raise CommandError("Bundle not found or missing file.")
            try:
                zip_path = str(Path(b.file.path))
            except Exception:
                raise CommandError("Bundle file path is not available in this storage backend.")

        if not zip_path:
            raise CommandError("Provide --zip or --bundle-id.")

        zpath = Path(zip_path)
        if not zpath.exists():
            raise CommandError(f"Zip not found: {zpath}")

        media_root = Path(opts.get("media_root") or settings.MEDIA_ROOT)

        if do_loaddata and not apply:
            raise CommandError("Refusing to run loaddata without --apply. This is intended for fresh/empty databases.")

        with zipfile.ZipFile(str(zpath), "r") as z:
            try:
                manifest_raw = z.read("manifest.json")
                manifest = json.loads(manifest_raw.decode("utf-8"))
            except Exception:
                manifest = {}

            self.stdout.write(f"Manifest org_id={manifest.get('organization_id')} org_name={manifest.get('organization_name')}")
            self.stdout.write(f"Backup version={manifest.get('homeglue_backup_version')}")

            if do_extract:
                n = _safe_extract_media(z=z, media_root=media_root)
                self.stdout.write(f"Extracted media files: {n} -> {media_root}")

            if do_loaddata:
                try:
                    fixture_raw = z.read("fixture.json")
                except KeyError:
                    raise CommandError("fixture.json not found in zip.")
                tmp_path = Path("/tmp/homeglue-restore-fixture.json")
                tmp_path.write_bytes(fixture_raw)
                self.stdout.write(f"Running loaddata: {tmp_path}")
                call_command("loaddata", str(tmp_path))
                self.stdout.write("loaddata complete.")

