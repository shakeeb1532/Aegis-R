from __future__ import annotations

import json
import urllib.request
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Deque


def _default_intake_url(site: str) -> str:
    # Logs intake v2.
    # Common sites: datadoghq.com, datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com
    site = (site or "datadoghq.com").strip()
    if site.startswith("http://") or site.startswith("https://"):
        return site.rstrip("/")
    return f"https://http-intake.logs.{site}/api/v2/logs"


def _decision_host(decision: dict) -> Optional[str]:
    event = decision.get("event")
    if isinstance(event, dict):
        ent = event.get("entity")
        if isinstance(ent, dict):
            host = ent.get("host") or ent.get("source")
            if host:
                return host
        host = event.get("source")
        if host:
            return host
    return decision.get("source") or decision.get("host")


@dataclass
class DatadogEmitter:
    """Send kept decisions to Datadog logs intake."""

    api_key: str
    site: str = "datadoghq.com"
    service: str = "noisegraph"
    source: str = "noisegraph"
    tags: Optional[str] = None
    intake_url: Optional[str] = None
    timeout_s: int = 5
    only_keep: bool = True
    buffer_max: int = 1000
    retry_base_s: float = 0.5
    retry_max_s: float = 10.0
    _buffer: Deque[dict] = field(default_factory=deque, init=False, repr=False)
    _next_retry_at: float = field(default=0.0, init=False, repr=False)
    _retry_delay_s: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        self.intake_url = self.intake_url or _default_intake_url(self.site)

    def _send(self, decision: dict) -> bool:
        host = _decision_host(decision)
        payload = [
            {
                "message": json.dumps(decision, separators=(",", ":")),
                "service": self.service,
                "ddsource": self.source,
                "ddtags": self.tags,
                "hostname": host,
            }
        ]
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.intake_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "DD-API-KEY": self.api_key,
                "User-Agent": "noisegraph/shipper",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                resp.read()
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

        # Drain buffer first.
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
