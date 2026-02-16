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

PORT="${HOMEGLUE_PORT:-8081}"
echo "Bringing up stack in $DEST (HOMEGLUE_PORT=$PORT) ..."
cd "$DEST"
HOMEGLUE_PORT="$PORT" docker compose up -d --build --pull=false

echo "Done."
echo "Open: http://localhost:$PORT/app/"
