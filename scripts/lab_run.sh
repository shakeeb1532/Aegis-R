#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-/tmp/aman_lab}"

mkdir -p "$OUT_DIR"

cd "$ROOT_DIR"

if [[ ! -x "${ROOT_DIR}/aman" ]]; then
  echo "[lab] Building aman binary..."
  go build -o aman ./cmd/aman
fi

if [[ ! -f "${OUT_DIR}/env.json" ]]; then
  echo "[lab] Creating minimal env.json..."
  cat > "${OUT_DIR}/env.json" <<'JSON'
{
  "hosts": [
    {"id": "win-01", "zone": "user-net", "critical": false},
    {"id": "srv-01", "zone": "secure-net", "critical": true}
  ],
  "identities": [
    {"id": "alice", "role": "user", "priv_level": "standard"},
    {"id": "admin", "role": "admin", "priv_level": "high"}
  ],
  "trust_boundaries": [
    {"id": "tb-1", "from": "user-net", "to": "secure-net", "mode": "allow"}
  ]
}
JSON
fi

if [[ ! -f "${OUT_DIR}/zero_trust_baseline.json" ]]; then
  echo "[lab] Running init-scan..."
  "${ROOT_DIR}/aman" init-scan -baseline "${OUT_DIR}/zero_trust_baseline.json" -out "${OUT_DIR}/init_scan_report.json"
fi

if [[ ! -f "${OUT_DIR}/events.json" ]]; then
  echo "[lab] Generating synthetic events..."
  "${ROOT_DIR}/aman" generate -out "${OUT_DIR}/events.json" -count 200 -seed 42
fi

: > "${OUT_DIR}/audit.log"
: > "${OUT_DIR}/approvals.log"

echo "[lab] Running assess..."
"${ROOT_DIR}/aman" assess \
  -in "${OUT_DIR}/events.json" \
  -env "${OUT_DIR}/env.json" \
  -rules "${ROOT_DIR}/data/rules.json" \
  -state "${OUT_DIR}/state.json" \
  -audit "${OUT_DIR}/audit.log" \
  -baseline "${OUT_DIR}/zero_trust_baseline.json" \
  -format json > "${OUT_DIR}/report.json"

echo "[lab] Assessment complete."
echo "Report: ${OUT_DIR}/report.json"
echo "Audit: ${OUT_DIR}/audit.log"

# Best-effort package if we can find a decision ID in audit log
DECISION_ID=$(grep -E '"id":' "${OUT_DIR}/audit.log" | head -n 1 | sed -E 's/.*"id"\s*:\s*"([^"]+)".*/\1/')
if [[ -n "${DECISION_ID}" ]]; then
  echo "[lab] Packaging evidence for decision: ${DECISION_ID}"
  "${ROOT_DIR}/aman" audit package \
    --decision "${DECISION_ID}" \
    --audit "${OUT_DIR}/audit.log" \
    --approvals "${OUT_DIR}/approvals.log" \
    --report "${OUT_DIR}/report.json" \
    --rules "${ROOT_DIR}/data/rules.json" \
    --policy "${ROOT_DIR}/data/policy.json" \
    --out "${OUT_DIR}/evidence_bundle.zip"
  echo "Bundle: ${OUT_DIR}/evidence_bundle.zip"
else
  echo "[lab] No decision ID found in audit.log; skipping package step."
fi

cat <<'EOF'

[lab] Next steps for the tester:
- Replace events.json with hand-crafted attack patterns.
- Re-run assess to validate feasibility/incomplete/conflicted behavior.
- Verify evidence bundles with: aman audit bundle-verify --bundle <zip>
EOF
