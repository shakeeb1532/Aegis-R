from __future__ import annotations
from pydantic import BaseModel, Field
from pathlib import Path

class EngineConfig(BaseModel):
    db_path: Path = Field(default=Path("./state/noisegraph.db"))
    decisions_jsonl: Path = Field(default=Path("./state/decisions.jsonl"))

    timebucket_minutes: int = 5
    ewma_alpha: float = 0.25
    min_rate_for_anomaly: float = 1.0
    ewma_alpha_min: float = 0.05
    ewma_alpha_max: float = 0.7

    escalate_risk: int = 70
    suppress_risk: int = 15
    warmup_events_per_template: int = 200
    warmup_risk_override: int = 30
    stable_min_count: int = 200
    stable_min_age_minutes: int = 60
    stable_score_threshold: float = 1.0
    stable_suppress_risk: int = 10
    policy_path: Path | None = None

    cluster_window_seconds: int = 600  # 10 min

    max_message_bytes: int = 16_384  # 16 KB per message
    max_body_bytes: int = 1_048_576  # 1 MB request body
    max_batch_events: int = 500
    db_flush_events: int = 200
    db_flush_seconds: float = 2.0
    baseline_cache_size: int = 50_000
    baseline_cache_ttl_s: float = 600.0
    edge_cache_size: int = 200_000
    edge_cache_ttl_s: float = 600.0
