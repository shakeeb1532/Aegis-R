from __future__ import annotations
from pathlib import Path
import orjson

def append_jsonl(path: Path, obj: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as f:
        f.write(orjson.dumps(obj))
        f.write(b"\n")


class JsonlEmitter:
    """Append each decision as a JSON line and track policy overrides."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.policy_overrides = {"whitelist": 0, "blacklist": 0}

    def emit(self, decision: dict) -> None:
        append_jsonl(self.path, decision)
        po = decision.get("policy_overridden")
        if po in self.policy_overrides:
            self.policy_overrides[po] += 1
