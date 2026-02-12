#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p data

# Always (re)generate baseline

go run ./cmd/aman init-scan -baseline data/zero_trust_baseline.json

# Keypair for approval signatures
if [ ! -f data/keypair.json ]; then
  go run ./cmd/aman keys -out data/keypair.json
fi

# Ensure support files exist
: > data/approvals.log
: > data/disagreements.log
: > data/audit.log
echo "[]" > data/analyst_profiles.json

if [ ! -f data/state.json ]; then
  echo "{}" > data/state.json
fi

# Synthetic failure scenario set
cat > data/failures_events.json <<'JSON'
[
  {
    "id": "e1",
    "time": "2026-02-06T01:00:00Z",
    "host": "host-1",
    "user": "alice",
    "type": "login_success",
    "details": {"geo": "US", "device": "laptop-1"}
  },
  {
    "id": "e2",
    "time": "2026-02-06T01:10:00Z",
    "host": "host-1",
    "user": "alice",
    "type": "login_success",
    "details": {"geo": "RU", "device": "unknown"}
  },
  {
    "id": "e3",
    "time": "2026-02-06T01:12:00Z",
    "host": "idp-1",
    "user": "alice",
    "type": "mfa_disabled",
    "details": {"method": "app", "reason": "user_action"}
  },
  {
    "id": "e4",
    "time": "2026-02-06T01:20:00Z",
    "host": "idp-1",
    "user": "alice",
    "type": "admin_group_change",
    "details": {"group": "Domain Admins", "action": "add"}
  },
  {
    "id": "e5",
    "time": "2026-02-06T01:30:00Z",
    "host": "host-2",
    "user": "alice",
    "type": "process_creation",
    "details": {"proc": "powershell", "cmd": "powershell -enc SQBFAE..."}
  },
  {
    "id": "e6",
    "time": "2026-02-06T01:35:00Z",
    "host": "host-2",
    "user": "alice",
    "type": "process_creation",
    "details": {"proc": "rundll32", "cmd": "rundll32.exe javascript:..."}
  },
  {
    "id": "e7",
    "time": "2026-02-06T01:40:00Z",
    "host": "host-2",
    "user": "alice",
    "type": "data_staging",
    "details": {"path": "C:\\temp\\archive.7z"}
  },
  {
    "id": "e8",
    "time": "2026-02-06T01:45:00Z",
    "host": "host-2",
    "user": "alice",
    "type": "large_outbound_transfer",
    "details": {"bytes": 987654321}
  },
  {
    "id": "e9",
    "time": "2026-02-06T01:50:00Z",
    "host": "host-2",
    "user": "alice",
    "type": "exfil_tool",
    "details": {"tool": "rclone"}
  },
  {
    "id": "e10",
    "time": "2026-02-06T01:52:00Z",
    "host": "host-2",
    "user": "alice",
    "type": "persistence_registry_run_key",
    "details": {"key": "HKCU\\...\\Run"}
  }
]
JSON

# Run assess to generate report and audit

go run ./cmd/aman assess \
  -in data/failures_events.json \
  -env data/env.json \
  -rules data/rules.json \
  -state data/state.json \
  -audit data/audit.log \
  -baseline data/zero_trust_baseline.json \
  -format json > data/report.json

# Start ingest API (optional)
go run ./cmd/aman ingest-http -addr :8080 &
INGEST_PID=$!
trap 'kill $INGEST_PID' EXIT
sleep 1

echo "Failure demo complete."
echo "Report: data/report.json"
echo "Audit log: data/audit.log"
