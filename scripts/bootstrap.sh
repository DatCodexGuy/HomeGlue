#!/usr/bin/env bash
set -euo pipefail

# HomeGlue bootstrap installer.
# Goal: enable a single-line install like:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)"
#
# This script clones/updates the repo into /opt/homeglue (default) and then runs ./scripts/install.sh.
#
# Private repo installs:
# - Prefer SSH: HOMEGLUE_REPO_URL=git@github.com:DatCodexGuy/HomeGlue.git ...
# - Ensure your SSH key is loaded and has repo access.

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

dir_has_files() {
  local d="$1"
  if [[ -z "${ROOT_PREFIX:-}" ]]; then
    [[ -n "$(ls -A "$d" 2>/dev/null || true)" ]]
    return
  fi
  $ROOT_PREFIX bash -c 'd="$1"; test -n "$(ls -A "$d" 2>/dev/null | head -n 1)"' _ "$d"
}

clone_repo() {
  local url="$1"
  local ref="$2"
  local dest="$3"
  if $ROOT_PREFIX git clone --depth 1 --branch "$ref" "$url" "$dest"; then
    return 0
  fi
  log
  log "Git clone failed."
  log "If the repo is private, re-run with:"
  log "  HOMEGLUE_REPO_URL=git@github.com:DatCodexGuy/HomeGlue.git bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/DatCodexGuy/HomeGlue/main/scripts/bootstrap.sh)\""
  log "And ensure your SSH key has access to the repo."
  exit 1
}

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
    if [[ -d "$DEST" ]] && dir_has_files "$DEST"; then
      # Common case: older bootstrap used the tarball path because git wasn't installed.
      # Convert to a git clone while preserving the existing .env (and Docker volumes).
      log "DEST exists but is not a git repo. Converting to git clone while preserving .env..."
      tmpdir="$($ROOT_PREFIX mktemp -d)"
      cleanup_tmp() { $ROOT_PREFIX rm -rf "$tmpdir" >/dev/null 2>&1 || true; }
      trap cleanup_tmp EXIT
      if $ROOT_PREFIX test -f "$DEST/.env"; then
        $ROOT_PREFIX cp "$DEST/.env" "$tmpdir/.env"
      fi
      $ROOT_PREFIX rm -rf "$DEST"
      clone_repo "$REPO_URL" "$REF" "$DEST"
      if $ROOT_PREFIX test -f "$tmpdir/.env"; then
        $ROOT_PREFIX cp "$tmpdir/.env" "$DEST/.env"
        $ROOT_PREFIX chmod 600 "$DEST/.env" >/dev/null 2>&1 || true
      fi
    else
      $ROOT_PREFIX rm -rf "$DEST"
      clone_repo "$REPO_URL" "$REF" "$DEST"
    fi
  fi
else
  # Git-less install: pull a tarball from GitHub and extract.
  # Note: this requires the repo to be publicly accessible, or the user must supply an authenticated URL via HOMEGLUE_TARBALL_URL.
  need_cmd curl
  need_cmd tar
  TARBALL_URL="${HOMEGLUE_TARBALL_URL:-https://github.com/DatCodexGuy/HomeGlue/archive/refs/heads/${REF}.tar.gz}"
  log "[1/3] Installing via tarball..."
  $ROOT_PREFIX mkdir -p "$(dirname "$DEST")"
  tmpdir="$(mktemp -d)"
  cleanup_tmp() { rm -rf "$tmpdir" >/dev/null 2>&1 || true; }
  trap cleanup_tmp EXIT
  curl -fsSL "$TARBALL_URL" -o "$tmpdir/homeglue.tgz"
  # Preserve existing .env if present.
  envbak=""
  if [[ -f "${DEST}/.env" ]]; then
    envbak="$tmpdir/.env"
    $ROOT_PREFIX cp "${DEST}/.env" "$envbak"
  fi
  $ROOT_PREFIX rm -rf "$DEST"
  $ROOT_PREFIX mkdir -p "$DEST"
  $ROOT_PREFIX tar -xzf "$tmpdir/homeglue.tgz" -C "$tmpdir"
  top="$(find "$tmpdir" -maxdepth 1 -type d -name 'HomeGlue-*' | head -n 1)"
  [[ -n "$top" ]] || die "Unexpected tarball format"
  $ROOT_PREFIX cp -a "$top/." "$DEST/"
  if [[ -n "${envbak:-}" && -f "$envbak" ]]; then
    $ROOT_PREFIX cp "$envbak" "$DEST/.env"
    $ROOT_PREFIX chmod 600 "$DEST/.env" >/dev/null 2>&1 || true
  fi
fi

log "[2/3] Running HomeGlue install..."
cd "$DEST"
# Pass through a few useful overrides even when ROOT_PREFIX is sudo.
$ROOT_PREFIX env -u HOMEGLUE_NO_PREREQS \
  HOMEGLUE_COMPOSE_PROJECT="${HOMEGLUE_COMPOSE_PROJECT:-}" \
  HOMEGLUE_PORT="${HOMEGLUE_PORT:-}" \
  bash ./scripts/install.sh

log "[3/3] Done."
