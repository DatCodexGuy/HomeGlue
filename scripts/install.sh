#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

compose() {
  # Prefer docker compose; fallback to docker-compose if installed.
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
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
  # Good-enough secret key (same character set as Django's startproject).
  alphabet = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)"
  print("".join(secrets.choice(alphabet) for _ in range(60)))
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
  set_kv "HOMEGLUE_SECRET_KEY" "$(py_rand django_secret)" "$ENV_FILE"
  set_kv "HOMEGLUE_FERNET_KEY" "$(py_rand fernet)" "$ENV_FILE"
  set_kv "POSTGRES_PASSWORD" "$(py_rand token 18)" "$ENV_FILE"
  set_kv "DJANGO_SUPERUSER_USERNAME" "admin" "$ENV_FILE"
  set_kv "DJANGO_SUPERUSER_EMAIL" "admin@example.local" "$ENV_FILE"
  set_kv "DJANGO_SUPERUSER_PASSWORD" "$(py_rand token 16)" "$ENV_FILE"
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
compose exec -T web python manage.py migrate --noinput

echo "[4/4] Ensuring default superuser exists..."
compose exec -T web python manage.py shell -c "import os; from django.contrib.auth import get_user_model; User=get_user_model(); u=os.environ.get('DJANGO_SUPERUSER_USERNAME','admin'); e=os.environ.get('DJANGO_SUPERUSER_EMAIL','admin@example.local'); p=os.environ.get('DJANGO_SUPERUSER_PASSWORD',''); obj, created = User.objects.get_or_create(username=u, defaults={'email': e}); obj.email = e; obj.is_staff = True; obj.is_superuser = True;  created and obj.set_password(p); obj.save(); print('created' if created else 'updated (password unchanged)')"

echo
echo "HomeGlue is running:"
echo "- Web app:  http://localhost:8080/app/"
echo "- Wiki:     http://localhost:8080/app/wiki/"
echo "- Admin:    http://localhost:8080/admin/"
echo "- API docs: http://localhost:8080/api/docs/"
echo
echo "Superuser credentials (from .env):"
echo "- username: $(grep -E '^DJANGO_SUPERUSER_USERNAME=' "$ENV_FILE" | cut -d= -f2-)"
if [[ "$CREATED_ENV" -eq 1 ]]; then
  echo "- password: $(grep -E '^DJANGO_SUPERUSER_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
else
  echo "- password: (unchanged; see your existing .env)"
fi
