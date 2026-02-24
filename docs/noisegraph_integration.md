# Noisegraph Integration (Vendored)

`noisegraph` is vendored under:
- `external/noisegraph`

This keeps it optional and separate from Aman decision authority.

## Install and Run Noisegraph (inside Aegis-R)
```bash
cd external/noisegraph
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start noisegraph API
noisegraph serve --db ./state/noisegraph.db --port 8099
```

In another terminal:
```bash
cd external/noisegraph
source .venv/bin/activate
python scripts/gen_sample_logs.py --out ./logs/sample.log --lines 500
noisegraph ship tail --path ./logs/sample.log --source mac.local --emit jsonl --jsonl-path ./state/decisions.jsonl
```

## Convert Noisegraph Decisions to Aman Events
### One-command wrapper (recommended)
```bash
go run ./cmd/aman system noisegraph-quickstart \
  -decisions external/noisegraph/state/decisions.jsonl \
  -events data/noisegraph_events.json \
  -report docs/noisegraph_quickstart.json \
  -rules data/rules.json
```

### Manual conversion (alternative)
```bash
cd /Users/shak1532/Downloads/Aegis-R
python3 scripts/noisegraph_to_aman.py \
  --in external/noisegraph/state/decisions.jsonl \
  --out data/noisegraph_events.json \
  --only keep,escalate
```

## Run Aman on Converted Events
```bash
go run ./cmd/aman reason -in data/noisegraph_events.json -rules data/rules.json -format json --ai-overlay
```

## Authority Boundary
- Noisegraph can reduce noise upstream.
- Aman remains the deterministic escalation authority (`escalated` only when causal feasibility passes).
