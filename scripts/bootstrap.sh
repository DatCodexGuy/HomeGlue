#!/usr/bin/env bash
set -euo pipefail

# HomeGlue bootstrap installer.
# Goal: enable a single-line install like:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
#
# This script clones/updates the repo into /opt/homeglue (default) and then runs ./scripts/install.sh.

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
  die "This installer needs root (or sudo) to write to /opt. Re-run as root or install sudo."
}

REPO_URL="${HOMEGLUE_REPO_URL:-https://github.com/DatCodexGuy/HomeGlue.git}"
REF="${HOMEGLUE_REF:-main}"
DEST="${HOMEGLUE_DIR:-/opt/homeglue}"

ROOT_PREFIX="$(as_root_prefix)"

need_cmd docker
need_cmd python3

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon not running or not accessible. Install Docker and ensure your user can run docker."
fi

log "HomeGlue bootstrap:"
log "- repo:   ${REPO_URL}"
log "- ref:    ${REF}"
log "- dest:   ${DEST}"
log

if command -v git >/dev/null 2>&1; then
  log "[1/3] Installing via git..."
  $ROOT_PREFIX mkdir -p "$(dirname "$DEST")"

  if [[ -d "${DEST}/.git" ]]; then
    log "Updating existing clone..."
    $ROOT_PREFIX git -C "$DEST" fetch --all --prune
    $ROOT_PREFIX git -C "$DEST" checkout -q "$REF" || true
    $ROOT_PREFIX git -C "$DEST" reset --hard "origin/${REF}"
  else
    if [[ -e "$DEST" && ! -d "$DEST" ]]; then
      die "DEST exists and is not a directory: $DEST"
    fi
    if [[ -d "$DEST" && -n "$(ls -A "$DEST" 2>/dev/null || true)" ]]; then
      die "DEST exists and is not empty (and not a git repo): $DEST"
    fi
    $ROOT_PREFIX rm -rf "$DEST"
    $ROOT_PREFIX git clone --depth 1 --branch "$REF" "$REPO_URL" "$DEST"
  fi
else
  # Git-less install: pull a tarball from GitHub and extract.
  # Note: this requires the repo to be publicly accessible, or the user must supply an authenticated URL via HOMEGLUE_TARBALL_URL.
  need_cmd curl
  need_cmd tar
  TARBALL_URL="${HOMEGLUE_TARBALL_URL:-https://github.com/DatCodexGuy/HomeGlue/archive/refs/heads/${REF}.tar.gz}"
  log "[1/3] Installing via tarball..."
  $ROOT_PREFIX mkdir -p "$DEST"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  curl -fsSL "$TARBALL_URL" -o "$tmpdir/homeglue.tgz"
  $ROOT_PREFIX rm -rf "$DEST"
  $ROOT_PREFIX mkdir -p "$DEST"
  $ROOT_PREFIX tar -xzf "$tmpdir/homeglue.tgz" -C "$tmpdir"
  top="$(find "$tmpdir" -maxdepth 1 -type d -name 'HomeGlue-*' | head -n 1)"
  [[ -n "$top" ]] || die "Unexpected tarball format"
  $ROOT_PREFIX cp -a "$top/." "$DEST/"
fi

log "[2/3] Running HomeGlue install..."
cd "$DEST"
$ROOT_PREFIX bash ./scripts/install.sh

log "[3/3] Done."
