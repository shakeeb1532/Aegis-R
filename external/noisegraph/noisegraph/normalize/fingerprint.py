from __future__ import annotations
import hashlib
import json

def fingerprint(template: str, entity: dict, event_type: str) -> str:
    payload = {"t": template, "e": entity, "k": event_type}
    b = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = hashlib.sha256(b).hexdigest()[:16]
    return f"fp_{h}"
