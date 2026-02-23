from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

K = TypeVar("K")
V = TypeVar("V")


@dataclass
class _Entry(Generic[V]):
    value: V
    ts: float


class LRUCache(Generic[K, V]):
    def __init__(self, max_size: int = 10000, ttl_s: float = 300.0):
        self.max_size = max_size
        self.ttl_s = ttl_s
        self._data: OrderedDict[K, _Entry[V]] = OrderedDict()

    def get(self, key: K) -> Optional[V]:
        now = time.monotonic()
        ent = self._data.get(key)
        if ent is None:
            return None
        if now - ent.ts > self.ttl_s:
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return ent.value

    def set(self, key: K, value: V) -> None:
        now = time.monotonic()
        self._data[key] = _Entry(value=value, ts=now)
        self._data.move_to_end(key)
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)

    def contains(self, key: K) -> bool:
        return self.get(key) is not None

    def clear(self) -> None:
        self._data.clear()
