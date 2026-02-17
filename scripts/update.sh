#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '%s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

if [[ ! -d .git ]]; then
  die "This install is not a git clone. Re-run the one-liner bootstrap to reinstall/upgrade HomeGlue."
fi

if ! command -v git >/dev/null 2>&1; then
  die "git is required to update. Install git, or re-run the one-liner bootstrap."
fi

if [[ -n "$(git status --porcelain 2>/dev/null || true)" && "${HOMEGLUE_FORCE_UPDATE:-}" != "1" ]]; then
  die "Local changes detected. Commit/stash them first, or re-run with HOMEGLUE_FORCE_UPDATE=1."
fi

ref="${HOMEGLUE_REF:-main}"
log "Updating HomeGlue (ref: ${ref})..."

git fetch --all --prune
git checkout -q "$ref" || true
git reset --hard "origin/${ref}"

log "Running installer (rebuild + migrate)..."
bash ./scripts/install.sh

