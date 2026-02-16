#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

compose() {
  # Prefer docker compose; fallback to docker-compose if installed.
  # Note: HOMEGLUE_COMPOSE_PROJECT is a convenience override for smoke tests and side-by-side installs.
  local -a project=()
  if [[ -n "${HOMEGLUE_COMPOSE_PROJECT:-}" ]]; then
    project=(-p "$HOMEGLUE_COMPOSE_PROJECT")
  fi
  if docker compose version >/dev/null 2>&1; then
    docker compose "${project[@]}" "$@"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "${project[@]}" "$@"
    return
  fi
  echo "ERROR: Docker Compose not found. Install Docker Engine + Compose plugin." >&2
  exit 1
}

py_rand() {
  python3 - "$@" <<'PY'
import base64, secrets, sys
mode = sys.argv[1] if len(sys.argv) > 1 else "token"
if mode == "django_secret":
  # Generate a Django SECRET_KEY that won't trigger docker compose variable interpolation warnings.
  # (Avoid `$` and other shell-ish characters. token_urlsafe only uses [A-Za-z0-9_-].)
  print(secrets.token_urlsafe(48))
elif mode == "fernet":
  print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
else:
  n = int(sys.argv[2]) if len(sys.argv) > 2 else 24
  print(secrets.token_urlsafe(n))
PY
}

set_kv() {
  local key="$1"
  local val="$2"
  local file="$3"
  if grep -qE "^${key}=" "$file"; then
    # shellcheck disable=SC2001
    local esc
    esc="$(printf '%s' "$val" | sed -e 's/[\\/&]/\\&/g')"
    sed -i -E "s/^${key}=.*/${key}=${esc}/" "$file"
  else
    printf '\n%s=%s\n' "$key" "$val" >>"$file"
  fi
}

get_kv() {
  local key="$1"
  local file="$2"
  grep -E "^${key}=" "$file" | head -n 1 | cut -d= -f2- || true
}

require_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "ERROR: Missing dependency: $c" >&2
    exit 1
  fi
}

require_cmd docker
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon not running or not accessible to current user." >&2
  exit 1
fi

ENV_FILE="${ROOT}/.env"
CREATED_ENV=0
if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "${ROOT}/.env.example" ]]; then
    cp "${ROOT}/.env.example" "$ENV_FILE"
  else
    : >"$ENV_FILE"
  fi
  CREATED_ENV=1
fi

# Ensure secrets exist for fresh installs. If .env already exists, do not mutate it
# (changing HOMEGLUE_FERNET_KEY will break decryption of existing secrets).
if command -v python3 >/dev/null 2>&1; then
  :
else
  echo "ERROR: python3 is required to generate secure defaults (install python3 or pre-fill .env manually)." >&2
  exit 1
fi

if [[ "$CREATED_ENV" -eq 1 ]]; then
  # Allow caller to override port for fresh installs (useful for smoke tests / running side-by-side).
  if [[ -n "${HOMEGLUE_PORT:-}" ]]; then
    set_kv "HOMEGLUE_PORT" "${HOMEGLUE_PORT}" "$ENV_FILE"
  else
    set_kv "HOMEGLUE_PORT" "8080" "$ENV_FILE"
  fi
  set_kv "HOMEGLUE_SECRET_KEY" "$(py_rand django_secret)" "$ENV_FILE"
  set_kv "HOMEGLUE_FERNET_KEY" "$(py_rand fernet)" "$ENV_FILE"
  set_kv "POSTGRES_PASSWORD" "$(py_rand token 18)" "$ENV_FILE"
  # Keep DATABASE_URL in sync with the generated DB password (settings.py reads DATABASE_URL).
  db_name="$(get_kv POSTGRES_DB "$ENV_FILE")"
  db_user="$(get_kv POSTGRES_USER "$ENV_FILE")"
  db_pass="$(get_kv POSTGRES_PASSWORD "$ENV_FILE")"
  db_name="${db_name:-homeglue}"
  db_user="${db_user:-homeglue}"
  db_pass="${db_pass:-change-me}"
  set_kv "DATABASE_URL" "postgres://${db_user}:${db_pass}@db:5432/${db_name}" "$ENV_FILE"
  set_kv "DJANGO_SUPERUSER_USERNAME" "admin" "$ENV_FILE"
  set_kv "DJANGO_SUPERUSER_EMAIL" "admin@example.local" "$ENV_FILE"
  set_kv "DJANGO_SUPERUSER_PASSWORD" "$(py_rand token 16)" "$ENV_FILE"
else
  # Existing .env: validate that required values are present and sane.
  fernet="$(get_kv HOMEGLUE_FERNET_KEY "$ENV_FILE")"
  secret="$(get_kv HOMEGLUE_SECRET_KEY "$ENV_FILE")"
  pgpw="$(get_kv POSTGRES_PASSWORD "$ENV_FILE")"
  dburl="$(get_kv DATABASE_URL "$ENV_FILE")"

  if [[ -z "$fernet" || "$fernet" == "change-me" ]]; then
    echo "ERROR: HOMEGLUE_FERNET_KEY is missing or still set to 'change-me' in $ENV_FILE" >&2
    echo "This breaks secrets encryption. Generate a valid key (base64 32-byte) and set it in .env." >&2
    exit 1
  fi
  # Validate fernet is urlsafe-base64 decodable to 32 bytes.
  python3 - "$fernet" <<'PY' || { echo "ERROR: HOMEGLUE_FERNET_KEY is not a valid Fernet key." >&2; exit 1; }
import base64, sys
key = (sys.argv[1] or "").encode("utf-8")
raw = base64.urlsafe_b64decode(key)
assert len(raw) == 32
PY

  if [[ -z "$secret" ]]; then
    echo "ERROR: HOMEGLUE_SECRET_KEY is missing in $ENV_FILE" >&2
    exit 1
  fi
  if [[ "$secret" == "change-me" ]]; then
    echo "WARNING: HOMEGLUE_SECRET_KEY is still set to 'change-me' in $ENV_FILE (insecure)." >&2
  fi
  if [[ -z "$pgpw" ]]; then
    echo "ERROR: POSTGRES_PASSWORD is missing in $ENV_FILE" >&2
    exit 1
  fi
  if [[ "$pgpw" == "change-me" ]]; then
    echo "WARNING: POSTGRES_PASSWORD is still set to 'change-me' in $ENV_FILE (insecure)." >&2
  fi
  if [[ -n "$dburl" && "$dburl" == *\":change-me@\"* && "$pgpw" != "change-me" ]]; then
    echo "WARNING: DATABASE_URL still contains ':change-me@' but POSTGRES_PASSWORD is different." >&2
    echo "If your database is new, update DATABASE_URL to match POSTGRES_PASSWORD." >&2
  fi
fi

chmod 600 "$ENV_FILE" || true

echo "[1/4] Building and starting containers..."
compose up -d --build

echo "[2/4] Waiting for web container to be ready..."
for i in {1..30}; do
  if compose exec -T web python -c "print('ok')" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[3/4] Running migrations..."
compose exec -T web python manage.py migrate_with_lock

echo "[4/4] Ensuring default superuser exists..."
if [[ "$CREATED_ENV" -eq 1 ]]; then
  compose exec -T -e HOMEGLUE_SET_SUPERUSER_PASSWORD=1 web python manage.py shell -c "import os; from django.contrib.auth import get_user_model; User=get_user_model(); u=os.environ.get('DJANGO_SUPERUSER_USERNAME','admin'); e=os.environ.get('DJANGO_SUPERUSER_EMAIL','admin@example.local'); p=os.environ.get('DJANGO_SUPERUSER_PASSWORD',''); force=os.environ.get('HOMEGLUE_SET_SUPERUSER_PASSWORD')=='1'; obj, created = User.objects.get_or_create(username=u, defaults={'email': e}); obj.email = e; obj.is_staff = True; obj.is_superuser = True;  (created or force) and obj.set_password(p); obj.save(); print('created' if created else ('updated (password set)' if force else 'updated (password unchanged)'))"
else
  compose exec -T web python manage.py shell -c "import os; from django.contrib.auth import get_user_model; User=get_user_model(); u=os.environ.get('DJANGO_SUPERUSER_USERNAME','admin'); e=os.environ.get('DJANGO_SUPERUSER_EMAIL','admin@example.local'); p=os.environ.get('DJANGO_SUPERUSER_PASSWORD',''); obj, created = User.objects.get_or_create(username=u, defaults={'email': e}); obj.email = e; obj.is_staff = True; obj.is_superuser = True;  created and obj.set_password(p); obj.save(); print('created' if created else 'updated (password unchanged)')"
fi

echo
PORT="$(get_kv HOMEGLUE_PORT "$ENV_FILE")"
PORT="${PORT:-8080}"
echo "HomeGlue is running:"
echo "- Web app:  http://localhost:${PORT}/app/"
echo "- Wiki:     http://localhost:${PORT}/app/wiki/"
echo "- Admin:    http://localhost:${PORT}/admin/"
echo "- API docs: http://localhost:${PORT}/api/docs/"
echo
echo "Superuser credentials (from .env):"
echo "- username: $(grep -E '^DJANGO_SUPERUSER_USERNAME=' "$ENV_FILE" | cut -d= -f2-)"
if [[ "$CREATED_ENV" -eq 1 ]]; then
  echo "- password: $(grep -E '^DJANGO_SUPERUSER_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
else
  echo "- password: (unchanged; see your existing .env)"
fi
