from __future__ import annotations
import hashlib
from datetime import datetime, timezone

def _parse(ts_iso: str) -> datetime:
    return datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).astimezone(timezone.utc)

def incident_id_for(event: dict, window_seconds: int) -> str:
    ts = _parse(event["ts"])
    win = int(ts.timestamp()) // window_seconds
    ent = event.get("entity", {}) or {}
    anchor = ent.get("user") or ent.get("service") or ent.get("source") or event.get("source") or "unknown"
    base = f"{event['fingerprint']}|{win}|{anchor}"
    h = hashlib.sha256(base.encode("utf-8")).hexdigest()[:12]
    return f"inc_{h}"
