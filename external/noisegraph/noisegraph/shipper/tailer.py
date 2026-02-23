from __future__ import annotations
from pathlib import Path
from typing import Iterator
from watchfiles import watch

def follow_file(path: Path, *, read_existing: bool = False) -> Iterator[str]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        # By default we emulate `tail -f` (start at EOF). For testing we allow
        # reading existing contents from the start.
        if not read_existing:
            f.seek(0, 2)  # end
        for _changes in watch(path.parent):
            while True:
                line = f.readline()
                if not line:
                    break
                yield line.rstrip("\n")
