#!/usr/bin/env python3
"""
Convert noisegraph decisions JSONL into Aman events JSON.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def pick_host(decision: dict[str, Any]) -> str:
    event = decision.get("event", {}) or {}
    entity = event.get("entity", {}) or {}
    for key in ("source", "host", "asset"):
        val = entity.get(key) or event.get(key) or decision.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return "unknown-host"


def pick_user(decision: dict[str, Any]) -> str:
    event = decision.get("event", {}) or {}
    entity = event.get("entity", {}) or {}
    for key in ("user", "principal"):
        val = entity.get(key) or event.get(key) or decision.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def to_aman_event(decision: dict[str, Any], index: int) -> dict[str, Any]:
    status = str(decision.get("decision", "keep")).strip().lower() or "keep"
    reasons = decision.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    event = decision.get("event", {}) or {}
    template = event.get("template", "")
    if not isinstance(template, str):
        template = str(template)

    return {
        "id": str(decision.get("fingerprint") or f"ng-{index}"),
        "time": str(decision.get("ts") or ""),
        "host": pick_host(decision),
        "user": pick_user(decision),
        "type": f"noisegraph_{status}",
        "details": {
            "source": "noisegraph",
            "decision": status,
            "risk": decision.get("risk"),
            "reasons": reasons,
            "template": template,
            "incident_id": decision.get("incident_id"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert noisegraph decisions JSONL into Aman events JSON.")
    parser.add_argument("--in", dest="in_path", required=True, help="Input noisegraph decisions JSONL path")
    parser.add_argument("--out", dest="out_path", required=True, help="Output Aman events JSON path")
    parser.add_argument(
        "--only",
        default="keep,escalate",
        help="Comma-separated decision statuses to include (default: keep,escalate)",
    )
    args = parser.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    include = {x.strip().lower() for x in str(args.only).split(",") if x.strip()}

    events: list[dict[str, Any]] = []
    with in_path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            decision = json.loads(raw)
            status = str(decision.get("decision", "")).strip().lower()
            if status not in include:
                continue
            events.append(to_aman_event(decision, idx))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
        f.write("\n")

    print(f"converted={len(events)} out={out_path}")


if __name__ == "__main__":
    main()
