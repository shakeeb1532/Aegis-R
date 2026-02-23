from __future__ import annotations
import re
from typing import Tuple

_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
_NUM = re.compile(r"\b\d+\b")
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_PATH = re.compile(r"(/[\w\-.]+)+")

def templateize(message: str) -> Tuple[str, dict]:
    fields = {}
    msg = message

    ips = _IP.findall(msg)
    if ips:
        fields["ip_candidates"] = ips[:5]
        msg = _IP.sub("*", msg)

    msg = _EMAIL.sub("*", msg)
    msg = _UUID.sub("*", msg)
    msg = _HEX.sub("*", msg)
    msg = _PATH.sub("*", msg)
    msg = _NUM.sub("*", msg)

    msg = re.sub(r"\s+", " ", msg).strip()
    return msg, fields
