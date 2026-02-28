#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/aman"
OUTDIR="${ROOT_DIR}/out/pilot/entra"
MINUTES="15"
START=""
END=""

usage() {
  cat <<'USAGE'
One-command Entra identity pilot run.

Requirements:
  - ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET env vars
  - ./aman built in repo root

Usage:
  scripts/entra_pilot.sh [--start RFC3339 --end RFC3339] [--minutes N] [--outdir PATH]

Examples:
  scripts/entra_pilot.sh --minutes 15
  scripts/entra_pilot.sh --start 2026-02-27T06:00:00Z --end 2026-02-27T06:15:00Z
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --start) START="${2:-}"; shift 2 ;;
    --end) END="${2:-}"; shift 2 ;;
    --minutes) MINUTES="${2:-}"; shift 2 ;;
    --outdir) OUTDIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${ENTRA_TENANT_ID:-}" || -z "${ENTRA_CLIENT_ID:-}" || -z "${ENTRA_CLIENT_SECRET:-}" ]]; then
  echo "Missing ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET env vars." >&2
  exit 1
fi

if [[ ! -x "${BIN}" ]]; then
  echo "Binary not found: ${BIN}" >&2
  echo "Build it first: go build -o aman ./cmd/aman" >&2
  exit 1
fi

if [[ -z "${START}" || -z "${END}" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to compute time windows." >&2
    exit 1
  fi
  read -r START END < <(python3 - <<PY
from datetime import datetime, timedelta, timezone
mins = int("${MINUTES}")
end = datetime.now(timezone.utc)
start = end - timedelta(minutes=mins)
print(start.replace(microsecond=0).isoformat().replace("+00:00","Z"),
      end.replace(microsecond=0).isoformat().replace("+00:00","Z"))
PY
)
fi

mkdir -p "${OUTDIR}"

exec "${BIN}" pilot identity-entra \
  --start "${START}" \
  --end "${END}" \
  --outdir "${OUTDIR}"

