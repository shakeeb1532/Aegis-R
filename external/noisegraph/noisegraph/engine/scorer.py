from __future__ import annotations
from dataclasses import dataclass
from typing import List

@dataclass
class ScoreResult:
    risk: int
    reasons: List[str]

def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))

def score_event(*, rate_anomaly: bool, first_seen_edges: int, rare_template: bool) -> ScoreResult:
    risk = 0
    reasons: List[str] = []
    if first_seen_edges:
        risk += 30 + min(30, 10 * (first_seen_edges - 1))
        reasons.append("new_graph_edge")
    if rate_anomaly:
        risk += 20
        reasons.append("rate_anomaly")
    if rare_template:
        risk += 15
        reasons.append("rare_template")
    return ScoreResult(risk=clamp(risk), reasons=reasons)
