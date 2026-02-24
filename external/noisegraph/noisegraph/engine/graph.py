from __future__ import annotations
import hashlib, json
from typing import List, Tuple

def edge_hash(src: str, dst: str, kind: str) -> str:
    payload = {"s": src, "d": dst, "k": kind}
    b = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "e_" + hashlib.sha256(b).hexdigest()[:16]

def extract_edges(event: dict) -> List[Tuple[str, str, str]]:
    ent = event.get("entity", {}) or {}
    source = ent.get("host") or ent.get("source") or event.get("source") or "unknown"
    edges: List[Tuple[str, str, str]] = []
    if "user" in ent:
        edges.append((f"user:{ent['user']}", f"host:{source}", "user_activity"))
    ips = (event.get("fields") or {}).get("ip_candidates") or []
    if ips:
        edges.append((f"ip:{ips[0]}", f"host:{source}", "ip_activity"))
    if "service" in ent:
        edges.append((f"host:{source}", f"svc:{ent['service']}", "host_calls_service"))
    return edges
