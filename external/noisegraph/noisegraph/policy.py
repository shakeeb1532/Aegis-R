from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List
import fnmatch
import re

import yaml


@dataclass
class Policy:
    whitelist: List[str]
    blacklist: List[str]

    def match_whitelist(self, template: str) -> bool:
        return _match_any(template, self.whitelist)

    def match_blacklist(self, template: str) -> bool:
        return _match_any(template, self.blacklist)


def _match_any(template: str, patterns: List[str]) -> bool:
    for p in patterns or []:
        p = p.strip()
        if not p:
            continue
        if p.startswith("regex:"):
            pat = p[len("regex:") :].strip()
            try:
                if re.search(pat, template):
                    return True
            except re.error:
                continue
        else:
            if fnmatch.fnmatch(template, p):
                return True
    return False


def load_policy(path: Path | None) -> Policy | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    data = yaml.safe_load(p.read_text()) or {}
    whitelist = data.get("whitelist") or []
    blacklist = data.get("blacklist") or []
    return Policy(whitelist=list(whitelist), blacklist=list(blacklist))
