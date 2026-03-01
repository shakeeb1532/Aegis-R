#!/usr/bin/env bash
set -euo pipefail

# Continuous Entra sign-in synthesizer -> ingest API
# Usage:
#   AMAN_INGEST_URL="http://localhost:8080/v1/ingest?schema=entra_signins_graph" \
#   AMAN_INGEST_API_KEY="your-key" \
#   scripts/entra_ingest_synth.sh --interval 30 --count 2

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out/synth/entra}"
INGEST_URL="${AMAN_INGEST_URL:-http://localhost:8080/v1/ingest?schema=entra_signins_graph}"
API_KEY="${AMAN_INGEST_API_KEY:-}"
INTERVAL="30"
COUNT="1"

usage() {
  cat <<'USAGE'
Entra synthetic ingest loop.

Env vars:
  AMAN_INGEST_URL     Ingest endpoint (default: http://localhost:8080/v1/ingest?schema=entra_signins_graph)
  AMAN_INGEST_API_KEY API key for ingest (optional)
  OUT_DIR             Output folder (default: out/synth/entra)

Flags:
  --interval N   Seconds between batches (default: 30)
  --count N      Sign-ins per batch (default: 1)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --count) COUNT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

mkdir -p "${OUT_DIR}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to synthesize Entra sign-ins." >&2
  exit 1
fi

echo "Writing synthetic Entra sign-ins to: ${OUT_DIR}"
echo "Posting to: ${INGEST_URL}"

while true; do
  ts="$(date -u +"%Y%m%dT%H%M%SZ")"
  raw="${OUT_DIR}/raw_signins_${ts}.json"
  resp="${OUT_DIR}/ingest_${ts}.json"

  python3 - <<PY > "${raw}"
import json, uuid, datetime, random
count = int("${COUNT}")
now = datetime.datetime.utcnow()

def gen(i):
    outcome = random.choice(["success","blocked","failed"])
    if outcome == "success":
        error = 0
        ca = "success"
        fail_reason = ""
    elif outcome == "blocked":
        error = 53003
        ca = "failure"
        fail_reason = "Conditional Access blocked"
    else:
        error = 50053
        ca = "notApplied"
        fail_reason = "Invalid credentials"

    risk_level = random.choice(["low","medium","high"])
    risk_state = random.choice(["none","atRisk","confirmedCompromised","remediated"])
    if risk_state == "none":
        risk_state = "none"

    return {
        "id": f"signin-{uuid.uuid4()}",
        "createdDateTime": (now - datetime.timedelta(seconds=i)).replace(microsecond=0).isoformat() + "Z",
        "userPrincipalName": f"user{i}@example.com",
        "userId": f"user-{i}",
        "tenantId": "tenant-1",
        "ipAddress": "203.0.113.10",
        "appDisplayName": "Office365",
        "resourceDisplayName": "Microsoft Graph",
        "conditionalAccessStatus": ca,
        "authenticationRequirement": "singleFactorAuthentication",
        "riskLevelAggregated": risk_level,
        "riskState": risk_state,
        "status": {
            "errorCode": error,
            "failureReason": fail_reason,
            "additionalDetails": ""
        },
        "deviceDetail": {
            "deviceId": f"device-{i}",
            "displayName": f"device-{i}",
            "isCompliant": random.choice([True, False]),
            "isManaged": random.choice([True, False]),
            "trustType": "workplace"
        },
        "authenticationDetails": [
            {
                "authenticationMethod": "Password",
                "succeeded": outcome == "success",
                "authenticationStepResultDetail": ""
            }
        ]
    }

payload = {"value": [gen(i) for i in range(count)]}
print(json.dumps(payload, indent=2))
PY

curl -sS -X POST "${INGEST_URL}" \
  -H "Content-Type: application/json" \
  ${API_KEY:+-H "X-API-Key: ${API_KEY}"} \
  -d @"${raw}" | tee "${resp}" >/dev/null

echo "Ingested ${COUNT} events -> ${resp}"
sleep "${INTERVAL}"
done

