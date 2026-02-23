#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p demo/data

python3 scripts/gen_realistic_logs.py --out demo/data/webapp.log --lines 5000 --profile webapp --format plain
python3 scripts/gen_realistic_logs.py --out demo/data/kubernetes.jsonl --lines 5000 --profile kubernetes --format jsonl
python3 scripts/gen_realistic_logs.py --out demo/data/cloudtrail.jsonl --lines 5000 --profile cloudtrail --format jsonl

python3 scripts/eval_noise_reduction.py --input demo/data/webapp.log --format plain --max-lines 5000 -b 200
python3 scripts/eval_noise_reduction.py --input demo/data/kubernetes.jsonl --format jsonl --message-field message --source-field source --stream-field stream --max-lines 5000 -b 200
python3 scripts/eval_noise_reduction.py --input demo/data/cloudtrail.jsonl --format jsonl --message-field message --source-field source --stream-field stream --max-lines 5000 -b 200
