from __future__ import annotations

import argparse
import collections
import json
import statistics
import tempfile
from pathlib import Path
import sys

from fastapi.testclient import TestClient

from noisegraph.api.server import create_app
from noisegraph.config import EngineConfig

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bench.gen_logs import line as gen_line


def run_synthetic(n: int, batch_size: int) -> None:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        cfg = EngineConfig(
            db_path=td_path / "db.sqlite",
            decisions_jsonl=td_path / "decisions.jsonl",
        )
        app = create_app(cfg)
        client = TestClient(app)

        decisions = []
        batch = []
        for _ in range(n):
            batch.append({"message": gen_line().strip(), "source": "bench", "stream": "bench"})
            if len(batch) >= batch_size:
                r = client.post("/ingest/batch", json={"events": batch})
                r.raise_for_status()
                decisions.extend(r.json()["items"])
                batch.clear()
        if batch:
            r = client.post("/ingest/batch", json={"events": batch})
            r.raise_for_status()
            decisions.extend(r.json()["items"])

        report(decisions)


def run_file(path: Path, batch_size: int, fmt: str, msg_field: str, source_field: str, stream_field: str, max_lines: int) -> None:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        cfg = EngineConfig(
            db_path=td_path / "db.sqlite",
            decisions_jsonl=td_path / "decisions.jsonl",
        )
        app = create_app(cfg)
        client = TestClient(app)

        decisions = []
        batch = []
        count = 0
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if max_lines and count >= max_lines:
                    break
                line = line.rstrip("\n")
                if not line:
                    continue
                count += 1
                if fmt == "jsonl":
                    try:
                        obj = json.loads(line)
                        msg = str(obj.get(msg_field, "")) if isinstance(obj, dict) else line
                        source = str(obj.get(source_field, "file")) if isinstance(obj, dict) else "file"
                        stream = str(obj.get(stream_field, "file")) if isinstance(obj, dict) else "file"
                    except Exception:
                        msg = line
                        source = "file"
                        stream = "file"
                else:
                    msg = line
                    source = "file"
                    stream = "file"
                batch.append({"message": msg, "source": source, "stream": stream})
                if len(batch) >= batch_size:
                    r = client.post("/ingest/batch", json={"events": batch})
                    r.raise_for_status()
                    decisions.extend(r.json()["items"])
                    batch.clear()
        if batch:
            r = client.post("/ingest/batch", json={"events": batch})
            r.raise_for_status()
            decisions.extend(r.json()["items"])

        report(decisions)


def report(decisions: list[dict]) -> None:
    counts = collections.Counter(d["decision"] for d in decisions)
    risks = [d["risk"] for d in decisions]
    total = len(decisions)

    suppress = counts.get("suppress", 0)
    deprioritize = counts.get("deprioritize", 0)
    keep = counts.get("keep", 0)
    escalate = counts.get("escalate", 0)

    noise_reduction = (suppress + deprioritize) / total * 100 if total else 0.0
    signal_rate = (keep + escalate) / total * 100 if total else 0.0

    print(f"Events: {total}")
    print(f"Decisions: {counts}")
    print(f"Noise reduction (suppress+deprioritize): {noise_reduction:.1f}%")
    print(f"Signal rate (keep+escalate): {signal_rate:.1f}%")
    if risks:
        qs = statistics.quantiles(risks, n=100)
        print(f"Risk p50/p90/p99: {qs[49]:.0f}/{qs[89]:.0f}/{qs[98]:.0f}")

    # Top templates suppressed/kept
    tmpl_supp = collections.Counter()
    tmpl_keep = collections.Counter()
    svc_reduction = collections.Counter()
    src_reduction = collections.Counter()
    for d in decisions:
        ev = d.get("event") or {}
        template = ev.get("template", "unknown")
        ent = ev.get("entity") or {}
        svc = ent.get("service", "unknown")
        src = ent.get("source", ev.get("source", "unknown"))
        if d["decision"] in {"suppress", "deprioritize"}:
            tmpl_supp[template] += 1
            svc_reduction[svc] += 1
            src_reduction[src] += 1
        if d["decision"] in {"keep", "escalate"}:
            tmpl_keep[template] += 1

    print("Top templates suppressed:")
    for tmpl, c in tmpl_supp.most_common(5):
        print(f"- {c} {tmpl}")
    print("Top templates kept:")
    for tmpl, c in tmpl_keep.most_common(5):
        print(f"- {c} {tmpl}")

    print("Reduction by service (supp+deprioritize counts):")
    for svc, c in svc_reduction.most_common(5):
        print(f"- {svc}: {c}")
    print("Reduction by source (supp+deprioritize counts):")
    for src, c in src_reduction.most_common(5):
        print(f"- {src}: {c}")

    # False-positive sampling: low-risk keep decisions
    fp_candidates = [d for d in decisions if d["decision"] == "keep" and d.get("risk", 0) <= 20]
    print("False-positive sampling (low-risk kept):")
    for d in fp_candidates[:5]:
        ev = d.get("event") or {}
        print(f"- risk={d.get('risk')} template={ev.get('template')} reasons={d.get('reasons')}")

    # Policy override summary
    policy_counts = collections.Counter(d.get("policy_overridden") for d in decisions)
    policy_counts.pop(None, None)
    if policy_counts:
        print("Policy overrides:")
        for k, v in policy_counts.items():
            print(f"- {k}: {v}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--num", type=int, default=20000)
    ap.add_argument("-b", "--batch-size", type=int, default=200)
    ap.add_argument("--input", type=Path, default=None)
    ap.add_argument("--format", choices=["plain", "jsonl"], default="plain")
    ap.add_argument("--message-field", default="message")
    ap.add_argument("--source-field", default="source")
    ap.add_argument("--stream-field", default="stream")
    ap.add_argument("--max-lines", type=int, default=0)
    args = ap.parse_args()
    if args.input:
        run_file(
            args.input,
            args.batch_size,
            args.format,
            args.message_field,
            args.source_field,
            args.stream_field,
            args.max_lines,
        )
    else:
        run_synthetic(args.num, args.batch_size)


if __name__ == "__main__":
    main()
