#!/usr/bin/env bash
set -euo pipefail

# Developer helper: deploy the current working tree into /opt and run docker compose there.
# This lets you test HomeGlue as it would be installed (canonical location: /opt/homeglue).
#
# Safe defaults:
# - Installs into /opt/homeglue-dev (does not clobber /opt/homeglue).
# - Uses HOMEGLUE_PORT=8081 so it can run alongside a dev stack on 8080.
#
# Usage:
#   scripts/dev_install_to_opt.sh
#   scripts/dev_install_to_opt.sh --path /opt/homeglue --force
#   HOMEGLUE_PORT=8082 scripts/dev_install_to_opt.sh

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEST="/opt/homeglue-dev"
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --path)
      DEST="${2:-}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      sed -n '1,120p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$DEST" ]]; then
  echo "--path requires a value" >&2
  exit 2
fi

if [[ -e "$DEST" && "$FORCE" -ne 1 ]]; then
  echo "Refusing to overwrite existing: $DEST" >&2
  echo "Re-run with --force if you really want to overwrite it." >&2
  exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "This script needs root (writes to /opt)." >&2
  exit 2
fi

mkdir -p "$DEST"

echo "Syncing to $DEST ..."
rsync -a --delete \
  --exclude ".git/" \
  --exclude ".env" \
  --exclude "media/" \
  --exclude "data/" \
  --exclude "backend/media/" \
  --exclude "backend/staticfiles/" \
  --exclude "docs/internal/" \
  --exclude "__pycache__/" \
  --exclude "*.pyc" \
  "$SRC_DIR/" "$DEST/"

chmod +x "$DEST/scripts/"*.sh 2>/dev/null || true

if [[ ! -f "$DEST/.env" ]]; then
  cp -n "$DEST/.env.example" "$DEST/.env" || true
fi

upsert_env() {
  local key="$1"
  local value="$2"
  local file="$3"
  if grep -qE "^${key}=" "$file"; then
    # shellcheck disable=SC2001
    local esc
    esc="$(printf '%s' "$value" | sed -e 's/[&/]/\\&/g')"
    sed -i -E "s#^${key}=.*#${key}=${esc}#g" "$file"
  else
    printf '\n%s=%s\n' "$key" "$value" >>"$file"
  fi
}

# Ensure required crypto keys exist in the /opt test install.
# `.env.example` intentionally contains placeholders which break secrets encryption.
fernet_raw="$(grep -E '^HOMEGLUE_FERNET_KEY=' "$DEST/.env" | head -n 1 | cut -d= -f2- || true)"
secret_raw="$(grep -E '^HOMEGLUE_SECRET_KEY=' "$DEST/.env" | head -n 1 | cut -d= -f2- || true)"
if [[ -z "${fernet_raw}" || "${fernet_raw}" == "change-me" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    fernet_raw="$(python3 - <<'PY'
import base64
import os

print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
  else
    echo "python3 is required to generate HOMEGLUE_FERNET_KEY" >&2
    exit 2
  fi
  upsert_env "HOMEGLUE_FERNET_KEY" "$fernet_raw" "$DEST/.env"
fi
if [[ -z "${secret_raw}" || "${secret_raw}" == "change-me" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    secret_raw="$(python3 - <<'PY'
import secrets

print(secrets.token_urlsafe(48))
PY
)"
  else
    echo "python3 is required to generate HOMEGLUE_SECRET_KEY" >&2
    exit 2
  fi
  upsert_env "HOMEGLUE_SECRET_KEY" "$secret_raw" "$DEST/.env"
fi

PORT="${HOMEGLUE_PORT:-8081}"
echo "Bringing up stack in $DEST (HOMEGLUE_PORT=$PORT) ..."
cd "$DEST"
HOMEGLUE_PORT="$PORT" docker compose build --pull=false
HOMEGLUE_PORT="$PORT" docker compose up -d --force-recreate

echo "Done."
echo "Open: http://localhost:$PORT/app/"
