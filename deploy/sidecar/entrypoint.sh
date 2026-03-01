#!/usr/bin/env sh
set -eu

if [ -z "${ENTRA_TENANT_ID:-}" ] || [ -z "${ENTRA_CLIENT_ID:-}" ] || [ -z "${ENTRA_CLIENT_SECRET:-}" ]; then
  echo "Missing ENTRA_* credentials." >&2
  exit 1
fi
if [ -z "${AMAN_INGEST_URL:-}" ] || [ -z "${AMAN_INGEST_API_KEY:-}" ]; then
  echo "Missing AMAN_INGEST_URL or AMAN_INGEST_API_KEY." >&2
  exit 1
fi

OUT_DIR="${OUT_DIR:-/data/entra}"
WINDOW_MINUTES="${WINDOW_MINUTES:-15}"
SLEEP_SECONDS="${SLEEP_SECONDS:-60}"

mkdir -p "${OUT_DIR}"

echo "Aman sidecar starting."
echo "Window: ${WINDOW_MINUTES}m, interval: ${SLEEP_SECONDS}s"
echo "Ingest: ${AMAN_INGEST_URL}"

while true; do
  ts="$(date -u +"%Y%m%dT%H%M%SZ")"
  end="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  start="$(date -u -d "${WINDOW_MINUTES} minutes ago" +"%Y-%m-%dT%H:%M:%SZ")"

  raw="${OUT_DIR}/raw_signins_${ts}.json"
  norm="${OUT_DIR}/normalized_${ts}.json"
  resp="${OUT_DIR}/ingest_${ts}.json"

  /usr/local/bin/aman ingest entra-pull \
    --start "${start}" \
    --end "${end}" \
    --out "${raw}"

  /usr/local/bin/aman ingest entra-normalize \
    --in "${raw}" \
    --out "${norm}"

  curl -sS -X POST "${AMAN_INGEST_URL}" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${AMAN_INGEST_API_KEY}" \
    -d @"${norm}" > "${resp}"

  echo "Pulled ${start} -> ${end}, ingested. Response: ${resp}"
  sleep "${SLEEP_SECONDS}"
done
