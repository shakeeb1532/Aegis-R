#!/usr/bin/env bash
set -euo pipefail

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

mkdir -p logs state
python scripts/gen_sample_logs.py --out ./logs/sample.log --lines 500

noisegraph serve --db ./state/noisegraph.db --port 8099 &
SERVER_PID=$!
sleep 1

noisegraph ship tail --path ./logs/sample.log --source mac.local

kill $SERVER_PID
