#!/usr/bin/env bash
set -euo pipefail

baseline="data/zero_trust_baseline.json"
report="data/report.json"
audit="data/audit.log"
state="data/state.json"
events="data/events.json"
keypair="data/keypair.json"
profiles="data/analyst_profiles.json"
disagreements="data/disagreements.log"
approvals="data/approvals.log"

mkdir -p data
: > "$approvals"
: > "$disagreements"
: > "$audit"
echo "[]" > "$profiles"

if [ ! -f "$baseline" ]; then
  go run ./cmd/aegisr init-scan -baseline "$baseline" -out data/init_scan_report.json
fi

go run ./cmd/aegisr keys -out "$keypair"
go run ./cmd/aegisr generate -out "$events" -count 80

go run ./cmd/aegisr assess \
  -in "$events" \
  -env data/env.json \
  -rules data/rules.json \
  -state "$state" \
  -audit "$audit" \
  -baseline "$baseline" \
  -format json > "$report"

go run ./cmd/aegisr ingest-http -addr :8080 &
INGEST_PID=$!
trap 'kill $INGEST_PID' EXIT
sleep 1
curl -s -X POST "http://localhost:8080/ingest?schema=ecs" -d @data/fixtures/ecs/sample.json >/dev/null || true

go run ./cmd/aegisr ui \
  -addr :9090 \
  -audit "$audit" \
  -signed-audit data/signed_audit.log \
  -approvals "$approvals" \
  -report "$report" \
  -profiles "$profiles" \
  -disagreements "$disagreements" \
  -key "$keypair" \
  -basic-user admin \
  -basic-pass pass
