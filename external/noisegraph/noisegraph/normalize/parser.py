from __future__ import annotations
import json
from datetime import datetime, timezone
import re
from typing import Dict, Tuple
from dateutil import parser as dtparse

from .templates import templateize
from .fingerprint import fingerprint as fp

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Common ISO8601 prefix: "2026-01-29T00:24:08.231178+00:00 <msg>"
_ISO_PREFIX_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(.*)$"
)

def parse_raw(message: str, source: str = "unknown", stream: str = "unknown") -> Tuple[dict, dict]:
    ts = _now_iso()
    raw = message.rstrip("\n")

    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            if "timestamp" in obj:
                try:
                    ts = dtparse.parse(str(obj["timestamp"])).astimezone(timezone.utc).isoformat()
                except Exception:
                    pass
            message = str(obj.get("message") or obj.get("msg") or raw)
            source = str(obj.get("source") or source)
            stream = str(obj.get("stream") or stream)
    except Exception:
        pass

    # If the (possibly extracted) message still starts with an ISO timestamp, peel it off.
    # This avoids polluting templates with per-line timestamps.
    m = _ISO_PREFIX_RE.match(message)
    if m:
        try:
            ts = dtparse.parse(m.group(1)).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
        message = m.group(2)

    template, partial = templateize(message)

    entity: Dict[str, str] = {"source": source}
    event_type = "log"
    lower = message.lower()

    if "ssh" in lower:
        entity["service"] = "ssh"
    if "failed password for" in lower or "invalid user" in lower:
        event_type = "auth_fail"
        parts = message.split()
        try:
            idx = [p.lower() for p in parts].index("for")
            if idx + 1 < len(parts):
                entity["user"] = parts[idx + 1]
        except Exception:
            pass

    fingerprint = fp(template=template, entity=entity, event_type=event_type)

    ev = {
        "ts": ts,
        "source": source,
        "stream": stream,
        "event_type": event_type,
        "entity": entity,
        "template": template,
        "fields": partial,
        "fingerprint": fingerprint,
        "severity_raw": "info",
        "raw": raw,
    }
    return ev, partial
