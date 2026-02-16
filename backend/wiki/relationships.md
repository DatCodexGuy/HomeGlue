# Relationships

Relationships link any two org-scoped objects (any-to-any).

## Relationship Types

Relationship Types are org-scoped and define the label shown in each direction.

Examples:

- “Runs On” / “Hosts”
- “Depends On” / “Depended On By”

Org admins manage relationship types.

## Object Linking

Most object detail pages show a Relationships panel where you can add links to other objects.

## Recommended Relationship Patterns

These patterns keep your documentation navigable:

- Asset -> Config Item:
  - “Hosts / Runs On”
- Config Item -> Password:
  - “Uses credential / Used by”
- Config Item -> Doc:
  - “Runbook / Applies to”
- Domain -> SSL cert:
  - link certificates to the domains they cover

## Relationship Types: Create Early

In a new org, create a small set of relationship types early so linking is consistent.

Start with:

- Runs On / Hosts
- Depends On / Depended On By
- Managed By / Manages
- Runbook / Applies To
