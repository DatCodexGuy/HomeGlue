# HomeGlue Wiki

This wiki documents HomeGlue functionality from a user/admin point of view.

Note: the in-app Wiki viewer reads markdown from `backend/wiki` so it ships with the Docker image. Keep `docs/wiki` and `backend/wiki` in sync.

## Core Concepts

- **Org-first navigation**: you must enter an Organization before viewing org-scoped data.
- **Roles**:
  - **Superuser**: global admin (creates orgs; can access all orgs)
  - **Org admin/owner**: can manage org-level configuration (relationship types, custom field definitions, workflows, etc.)
  - **Org member**: day-to-day usage (assets, docs, passwords, checklists, etc.)

## Pages

- HomeGlue Documentation (setup, requirements, features): `docs/wiki/documentation.md`
- Organizations and Memberships: `docs/wiki/organizations.md`
- Security (IP allowlist + OIDC): `docs/wiki/security.md`
- Assets and Inventory: `docs/wiki/assets.md`
- Config Items: `docs/wiki/config-items.md`
- Documents and Templates: `docs/wiki/docs.md`
- Passwords and Folders: `docs/wiki/passwords.md`
- Relationships: `docs/wiki/relationships.md`
- Checklists (Templates, Runs, Schedules): `docs/wiki/checklists.md`
- Workflows and Notifications (Email/Webhooks): `docs/wiki/workflows.md`
- API (Auth + Org Scoping): `docs/wiki/api.md`
- Proxmox Integration: `docs/wiki/integrations-proxmox.md`
