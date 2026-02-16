# Backups and Restore

HomeGlue backups are **organization snapshot bundles**: a zip file containing your org data (as a Django fixture) plus your attachments under `media/`.

Backups are intentionally **org-scoped**. There is no combined-org “export everything” view.

## Creating Snapshots

Go to `Backups` in the left sidebar.

- **Create snapshot**: creates a one-off snapshot request. The `worker` container builds the zip in the background.
- **Automation policy**: when enabled, the worker will enqueue snapshots on an interval and keep only the newest N successful snapshots.

## What’s Included

Snapshots include the org and most org-scoped data (assets, config items, docs, passwords, domains/SSL, checklists, workflows, relationships, custom fields, notes, integrations), plus attachment binaries.

## Restore (Current)

Restore is still safest when restoring into a **fresh HomeGlue stack** (empty DB + empty media volume).

### Guided Restore Wizard (UI)

Go to `Backups` and click `Restore wizard` to:

- Upload a backup zip to validate it (checks `manifest.json` + `fixture.json`)
- Download `manifest.json` and `fixture.json`
- Extract the `media/` contents into this instance's `MEDIA_ROOT`

Database restore remains an operator action; restoring into a non-empty DB can cause conflicts.

### Manual Restore Steps

High-level steps:

1. Extract the zip.
2. Copy `media/` into `MEDIA_ROOT` (default inside containers: `/data/media`).
3. Load `fixture.json` with Django `loaddata`.

Example:

```bash
docker compose exec -T web python manage.py loaddata /path/to/fixture.json
```

Notes:

- Restoring into a non-empty database can cause primary key conflicts.
- The UI restore wizard helps validate/extract; full automated restore is still tracked under backups parity v2.

### Recommended “Fresh Stack” Restore (Operator Workflow)

This is the safest approach today.

1. Bring down the stack and remove volumes (this deletes current DB + media):

```bash
cd /opt/homeglue
docker compose down -v
docker compose up -d --build
docker compose exec -T web python manage.py migrate --noinput
```

2. Restore media:

- Use the UI restore wizard to extract media into `/data/media`, or copy it manually into the media volume.

3. Restore DB data (fixture):

```bash
docker compose exec -T web python manage.py loaddata /path/to/fixture.json
```

4. Verify:

- login
- enter the org
- spot-check a few docs/assets/passwords and confirm attachments are downloadable
