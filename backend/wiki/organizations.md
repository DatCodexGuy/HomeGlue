# Organizations and Memberships

## Organization Scope

Most objects in HomeGlue are **organization-scoped** (assets, docs, passwords, domains, SSL certs, checklists, workflows).

HomeGlue intentionally does not show “combined org” views. Users must select which organization they are working in.

## Entering an Organization (UI)

1. Go to `/app/`
2. Pick an org
3. HomeGlue stores the “current org” in the session

Use “Switch Org” in the sidebar to leave the current org.

## Roles

- **Superuser**:
  - Can create organizations
  - Can access any organization
- **Org admin / owner**:
  - Can manage org-level configuration (relationship types, custom field definitions, workflows)
  - Can archive/restore objects
- **Org member**:
  - Can create/edit most org objects

## Default Organization

Users can set a default org in `Account`. This is used by the API when an explicit org is not provided.
