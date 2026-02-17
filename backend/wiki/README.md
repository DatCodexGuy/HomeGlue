# HomeGlue Wiki

This wiki documents HomeGlue functionality from a user/admin point of view.

Note: the in-app Wiki viewer reads markdown from `backend/wiki` so it ships with the Docker image.

## Core Concepts

- **Org-first navigation**: you must enter an Organization before viewing org-scoped data.
- **Roles**:
  - **Superuser**: global admin (creates orgs; can access all orgs)
  - **Org admin/owner**: can manage org-level configuration (relationship types, custom field definitions, workflows, etc.)
  - **Org member**: day-to-day usage (assets, docs, passwords, checklists, etc.)

## Pages

- HomeGlue Documentation (setup, requirements, features): `backend/wiki/documentation.md`
- Organizations and Memberships: `backend/wiki/organizations.md`
- Security (IP allowlist + OIDC): `backend/wiki/security.md`
- Assets and Inventory: `backend/wiki/assets.md`
- Config Items: `backend/wiki/config-items.md`
- Documents and Templates: `backend/wiki/docs.md`
- Passwords and Folders: `backend/wiki/passwords.md`
- Relationships: `backend/wiki/relationships.md`
- Checklists (Templates, Runs, Schedules): `backend/wiki/checklists.md`
- Workflows and Notifications (Email/Webhooks): `backend/wiki/workflows.md`
- API (Auth + Org Scoping): `backend/wiki/api.md`
- Proxmox Integration: `backend/wiki/integrations-proxmox.md`
