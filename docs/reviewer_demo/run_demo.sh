#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${1:-$ROOT/docs/reviewer_demo/out}"

mkdir -p "$OUTDIR"

cp "$ROOT/data/demo_events.json" "$OUTDIR/events.json"
cp "$ROOT/data/env.json" "$OUTDIR/env.json"
printf '{}\n' > "$OUTDIR/state.json"
: > "$OUTDIR/audit.log"
: > "$OUTDIR/approvals.log"

go run "$ROOT/cmd/aman" assess \
  -in "$OUTDIR/events.json" \
  -env "$OUTDIR/env.json" \
  -state "$OUTDIR/state.json" \
  -audit "$OUTDIR/audit.log" \
  -rules "$ROOT/data/rules.json" \
  -policy "$ROOT/data/policy.json" \
  -format json \
  -out "$OUTDIR/report.json" \
  > "$OUTDIR/assess.stdout"

DECISION_ID="$(
python3 - <<'PY' "$OUTDIR/audit.log"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    rows = [line for line in f if line.strip()]
print(json.loads(rows[-1])["id"])
PY
)"

go run "$ROOT/cmd/aman" audit package \
  --decision "$DECISION_ID" \
  --audit "$OUTDIR/audit.log" \
  --approvals "$OUTDIR/approvals.log" \
  --report "$OUTDIR/report.json" \
  --rules "$ROOT/data/rules.json" \
  --policy "$ROOT/data/policy.json" \
  --controls-json \
  --out "$OUTDIR/evidence.zip" \
  > "$OUTDIR/package.stdout"

go run "$ROOT/cmd/aman" audit bundle-verify \
  --bundle "$OUTDIR/evidence.zip" \
  > "$OUTDIR/verify.stdout"

python3 - <<'PY' "$OUTDIR/report.json" "$OUTDIR/cli_summary.txt" "$DECISION_ID"
import json, sys
report_path, out_path, decision_id = sys.argv[1:4]
with open(report_path, "r", encoding="utf-8") as f:
    report = json.load(f)

results = report["reasoning"]["results"]
feasible = [r for r in results if r.get("feasible")]
top = feasible[:8]
next_moves = report.get("next_moves", [])[:5]

lines = []
lines.append("Aman reviewer demo")
lines.append("")
lines.append(f"Decision ID: {decision_id}")
lines.append(f"Total rules evaluated: {len(results)}")
lines.append(f"Feasible findings: {len(feasible)}")
lines.append("")
lines.append("Top feasible findings:")
for item in top:
    lines.append(f"- {item['rule_id']} | {item['name']} | confidence={item['confidence']:.2f}")
lines.append("")
lines.append("Next moves:")
for move in next_moves:
    lines.append(f"- {move}")

with open(out_path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
PY

cat <<EOF
Reviewer demo complete.

Output directory: $OUTDIR
Decision ID: $DECISION_ID

Files:
- $OUTDIR/report.json
- $OUTDIR/audit.log
- $OUTDIR/evidence.zip
- $OUTDIR/cli_summary.txt
- $OUTDIR/verify.stdout
EOF
