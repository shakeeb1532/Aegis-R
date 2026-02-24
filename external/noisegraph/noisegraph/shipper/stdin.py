from __future__ import annotations
import sys
from typing import Iterator

def read_stdin() -> Iterator[str]:
    for line in sys.stdin:
        yield line.rstrip("\n")
