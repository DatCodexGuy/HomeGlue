#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${HOMEGLUE_COMPOSE_FILE:-docker-compose.yml}"

compose() {
  local -a project=()
  if [[ -n "${HOMEGLUE_COMPOSE_PROJECT:-}" ]]; then
    project=(-p "$HOMEGLUE_COMPOSE_PROJECT")
  fi
  if docker compose version >/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" "${project[@]}" "$@"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "$COMPOSE_FILE" "${project[@]}" "$@"
    return
  fi
  echo "ERROR: Docker Compose not found. Install Docker Engine + Compose plugin." >&2
  exit 1
}

echo "[1/3] Pulling latest images..."
compose pull

echo "[2/3] Restarting containers..."
compose up -d

echo "[3/3] Running migrations..."
compose exec -T web python manage.py migrate_with_lock

echo "Update complete."

