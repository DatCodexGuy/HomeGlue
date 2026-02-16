# API

HomeGlue provides a REST API for integration and automation.

## Authentication

HomeGlue supports:

- Session auth (browser)
- DRF token auth (personal access tokens)
- JWT (SimpleJWT)

Personal API tokens are managed in the UI:

- `/app/account/`

### Re-auth For Sensitive Endpoints

Some endpoints (for example password reveal and TOTP) require a short-lived re-auth token.

1. `POST /api/me/reauth/` with `{ "password": "..." }`
2. Use the returned token on subsequent calls:
- `X-HomeGlue-Reauth: <token>`

## API Docs

- OpenAPI schema: `/api/schema/`
- Swagger UI: `/api/docs/`
- Redoc: `/api/redoc/`

## Filtering and Ordering

Most org-scoped list endpoints support:

- `q`: text search across a handful of model fields
- `tag` or `tags`: filter by tag name/id (for taggable models)
- `ordering`: order results, e.g. `?ordering=name` or `?ordering=-updated_at`

## Org Scoping

Most endpoints require an explicit organization context (no combined views).

Preferred shape:

- `/api/orgs/<org_id>/...`

Also supported:

- Query param: `?org=<id>`
- Header: `X-HomeGlue-Org: <id>`

If org context is omitted, the API uses the user’s default org (if set).

## Examples (curl)

Get your profile:

```bash
curl -sS -H "Authorization: Token <token>" http://localhost:8080/api/me/
```

List assets in an org:

```bash
curl -sS -H "Authorization: Token <token>" http://localhost:8080/api/orgs/<org_id>/assets/
```

Using header org scoping:

```bash
curl -sS \\
  -H "Authorization: Token <token>" \\
  -H "X-HomeGlue-Org: <org_id>" \\
  http://localhost:8080/api/assets/
```
