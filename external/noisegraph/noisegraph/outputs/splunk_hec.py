from __future__ import annotations

import json
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional, Deque


def _decision_host(decision: dict, host_field: str) -> Optional[str]:
    event = decision.get("event")
    if isinstance(event, dict):
        ent = event.get("entity")
        if isinstance(ent, dict):
            host = ent.get(host_field) or ent.get("source") or ent.get("host")
            if host:
                return host
        host = event.get(host_field) or event.get("source")
        if host:
            return host
    return decision.get(host_field) or decision.get("source") or decision.get("host")


@dataclass
class SplunkHecEmitter:
    """Send kept decisions to Splunk via HTTP Event Collector (HEC)."""

    hec_url: str
    token: str
    index: Optional[str] = None
    sourcetype: str = "noisegraph"
    host_field: str = "source"
    only_keep: bool = True
    timeout_s: float = 5.0
    buffer_max: int = 1000
    retry_base_s: float = 0.5
    retry_max_s: float = 10.0
    _buffer: Deque[dict] = field(default_factory=deque, init=False, repr=False)
    _next_retry_at: float = field(default=0.0, init=False, repr=False)
    _retry_delay_s: float = field(default=0.0, init=False, repr=False)

    def _send(self, decision: dict) -> bool:
        ts = decision.get("ts")
        t_epoch: Optional[float] = None
        if isinstance(ts, str):
            try:
                import datetime as _dt

                t_epoch = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                t_epoch = None
        if t_epoch is None:
            t_epoch = time.time()

        host = _decision_host(decision, self.host_field)
        payload: dict[str, Any] = {
            "time": t_epoch,
            "host": host or "noisegraph",
            "sourcetype": self.sourcetype,
            "event": decision,
        }
        if self.index:
            payload["index"] = self.index

        data = json.dumps(payload).encode("utf-8")
        hec_url = self.hec_url.rstrip("/")
        if hec_url.endswith("/services/collector/event"):
            event_url = hec_url
        else:
            event_url = hec_url + "/services/collector/event"

        req = urllib.request.Request(
            event_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Splunk {self.token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as _:
                pass
            return True
        except Exception:
            return False

    def emit(self, decision: dict) -> None:
        if self.only_keep and decision.get("decision") != "keep":
            return

        now = time.monotonic()
        if now < self._next_retry_at:
            if len(self._buffer) < self.buffer_max:
                self._buffer.append(decision)
            return

        while self._buffer:
            item = self._buffer[0]
            if self._send(item):
                self._buffer.popleft()
                self._retry_delay_s = 0.0
                continue
            self._retry_delay_s = min(
                self.retry_max_s, self.retry_base_s if self._retry_delay_s == 0 else self._retry_delay_s * 2
            )
            self._next_retry_at = now + self._retry_delay_s
            return

        if not self._send(decision):
            if len(self._buffer) < self.buffer_max:
                self._buffer.append(decision)
            self._retry_delay_s = min(
                self.retry_max_s, self.retry_base_s if self._retry_delay_s == 0 else self._retry_delay_s * 2
            )
            self._next_retry_at = now + self._retry_delay_s
        else:
            self._retry_delay_s = 0.0
