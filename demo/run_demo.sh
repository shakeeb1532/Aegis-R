#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BASELINE="data/zero_trust_baseline.json"
if [ ! -f "${BASELINE}" ]; then
  echo "Creating zero-trust baseline..."
  go run ./cmd/aegisr init-scan -baseline "${BASELINE}"
fi

# CloudTrail demo
CLOUD_DIR="data/fixtures/splunk_attack_data"
COMBINED="${CLOUD_DIR}/combined_cloudtrail.json"
INGESTED="${CLOUD_DIR}/ingested_events.json"
STATE="${CLOUD_DIR}/state.json"
AUDIT="${CLOUD_DIR}/audit.log"
SIEM="${CLOUD_DIR}/siem.json"
ASSESS_RAW="${CLOUD_DIR}/assessment.json"
ASSESS_CLEAN="${CLOUD_DIR}/assessment_clean.json"

if ls ${CLOUD_DIR}/*_array.json >/dev/null 2>&1; then
  jq -s 'map(select(type=="array")) | add | flatten' ${CLOUD_DIR}/*_array.json > "${COMBINED}"
fi

go run ./cmd/aegisr ingest file \
  -in "${COMBINED}" \
  -schema aws_cloudtrail \
  -out "${INGESTED}"

echo '{}' > "${STATE}"

go run ./cmd/aegisr --quiet assess \
  -in "${INGESTED}" \
  -env data/env.json \
  -state "${STATE}" \
  -audit "${AUDIT}" \
  -siem "${SIEM}" \
  -rules data/rules.json \
  -config data/ops.json \
  -baseline "${BASELINE}" \
  -format json \
  -admin-approval data/admin_approval.json \
  > "${ASSESS_RAW}"

awk 'BEGIN{p=0} /^{/{p=1} {if(p) print}' "${ASSESS_RAW}" > "${ASSESS_CLEAN}"

echo "CloudTrail demo complete: ${ASSESS_CLEAN}"

# Windows Event Log demo
WIN_DIR="data/fixtures/securitydatasets"
WIN_INPUT="${WIN_DIR}/cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
WIN_INGESTED="${WIN_DIR}/ingested_events.json"
WIN_STATE="${WIN_DIR}/state.json"
WIN_AUDIT="${WIN_DIR}/audit.log"
WIN_SIEM="${WIN_DIR}/siem.json"
WIN_ASSESS_RAW="${WIN_DIR}/assessment.json"
WIN_ASSESS_CLEAN="${WIN_DIR}/assessment_clean.json"
WIN_CFG="${WIN_DIR}/ops_strict.json"

if [ ! -f "${WIN_INPUT}" ]; then
  echo "Windows demo dataset not found: ${WIN_INPUT}"
  exit 1
fi

if [ ! -f "${WIN_CFG}" ]; then
  cat <<'CFG' > "${WIN_CFG}"
{
  "log_level": "info",
  "metrics_on": true,
  "strict_mode": true
}
CFG
fi

go run ./cmd/aegisr ingest file \
  -in "${WIN_INPUT}" \
  -schema windows_eventlog \
  -out "${WIN_INGESTED}"

echo '{}' > "${WIN_STATE}"

go run ./cmd/aegisr --quiet assess \
  -in "${WIN_INGESTED}" \
  -env data/env.json \
  -state "${WIN_STATE}" \
  -audit "${WIN_AUDIT}" \
  -siem "${WIN_SIEM}" \
  -rules data/rules.json \
  -config "${WIN_CFG}" \
  -baseline "${BASELINE}" \
  -format json \
  -admin-approval data/admin_approval.json \
  > "${WIN_ASSESS_RAW}"

awk 'BEGIN{p=0} /^{/{p=1} {if(p) print}' "${WIN_ASSESS_RAW}" > "${WIN_ASSESS_CLEAN}"

echo "Windows demo complete: ${WIN_ASSESS_CLEAN}"
