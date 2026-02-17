#!/usr/bin/env bash
set -euo pipefail

# HomeGlue bootstrap installer/updater (Docker image based).
#
# One-liner:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
#
# Design:
# - No git required on the target host.
# - Downloads the deployment files into /opt/homeglue (default).
# - Runs ./scripts/install.sh which installs prerequisites, pulls images, and starts the stack.

log() { printf '%s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

as_root_prefix() {
  if [[ "$(id -u)" -eq 0 ]]; then
    echo ""
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    echo "sudo"
    return
  fi
  die "This installer needs root (or sudo) to write to /opt and install prerequisites."
}

RAW_BASE="${HOMEGLUE_RAW_BASE:-https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main}"
DEST="${HOMEGLUE_DIR:-/opt/homeglue}"

ROOT_PREFIX="$(as_root_prefix)"

need_cmd curl

log "HomeGlue bootstrap (image-based):"
log "- raw:    ${RAW_BASE}"
log "- dest:   ${DEST}"
log

$ROOT_PREFIX mkdir -p "$DEST/scripts"

# Preserve .env across bootstrap upgrades.
if $ROOT_PREFIX test -f "$DEST/.env"; then
  $ROOT_PREFIX cp "$DEST/.env" "$DEST/.env.bak"
fi

log "[1/3] Downloading deployment files..."
$ROOT_PREFIX curl -fsSL "${RAW_BASE}/docker-compose.yml" -o "$DEST/docker-compose.yml"
$ROOT_PREFIX curl -fsSL "${RAW_BASE}/.env.example" -o "$DEST/.env.example" || true
$ROOT_PREFIX curl -fsSL "${RAW_BASE}/scripts/install.sh" -o "$DEST/scripts/install.sh"
$ROOT_PREFIX curl -fsSL "${RAW_BASE}/scripts/update.sh" -o "$DEST/scripts/update.sh"

$ROOT_PREFIX chmod +x "$DEST/scripts/install.sh" "$DEST/scripts/update.sh" || true

if $ROOT_PREFIX test -f "$DEST/.env.bak" && ! $ROOT_PREFIX test -f "$DEST/.env"; then
  $ROOT_PREFIX mv "$DEST/.env.bak" "$DEST/.env"
fi
if $ROOT_PREFIX test -f "$DEST/.env.bak"; then
  $ROOT_PREFIX rm -f "$DEST/.env.bak" || true
fi

log "[2/3] Running installer..."
cd "$DEST"
$ROOT_PREFIX env -u HOMEGLUE_NO_PREREQS \
  # Bootstrap should always bring the install to the latest image, even if /opt/homeglue/.env pins HOMEGLUE_IMAGE.
  HOMEGLUE_IMAGE="ghcr.io/datcodexguy/homeglue:latest" \
  HOMEGLUE_COMPOSE_PROJECT="${HOMEGLUE_COMPOSE_PROJECT:-}" \
  HOMEGLUE_PORT="${HOMEGLUE_PORT:-}" \
  bash ./scripts/install.sh

log "[3/3] Done."
