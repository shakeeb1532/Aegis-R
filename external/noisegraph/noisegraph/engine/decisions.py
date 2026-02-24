from __future__ import annotations

def decide(risk: int, escalate_risk: int, suppress_risk: int) -> str:
    if risk >= escalate_risk:
        return "escalate"
    if risk <= suppress_risk:
        return "suppress"
    if risk < int(escalate_risk * 0.6):
        return "deprioritize"
    return "keep"

def explain(decision: str, reasons: list[str]) -> str:
    if not reasons:
        return "No strong anomaly signals observed; classified by thresholds."
    return f"{decision.upper()}: " + ", ".join(reasons[:4])
