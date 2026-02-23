from fastapi.testclient import TestClient
from pathlib import Path
from noisegraph.api.server import create_app
from noisegraph.config import EngineConfig
import json

def test_ingest_returns_decision(tmp_path: Path):
    cfg = EngineConfig(db_path=tmp_path/"db.sqlite", decisions_jsonl=tmp_path/"decisions.jsonl")
    app = create_app(cfg)
    c = TestClient(app)
    r = c.post("/ingest", json={"message":"Failed password for admin from 1.2.3.4 port 2222 ssh2","source":"mac"})
    assert r.status_code == 200
    d = r.json()
    assert "decision" in d and "risk" in d and "incident_id" in d

def test_ingest_batch(tmp_path: Path):
    cfg = EngineConfig(db_path=tmp_path/"db.sqlite", decisions_jsonl=tmp_path/"decisions.jsonl")
    app = create_app(cfg)
    c = TestClient(app)
    payload = {
        "events": [
            {"message": "Failed password for admin from 1.2.3.4 port 2222 ssh2", "source": "mac"},
            {"message": "Failed password for root from 5.6.7.8 port 2222 ssh2", "source": "mac"},
        ]
    }
    r = c.post("/ingest/batch", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2
    assert len(data["items"]) == 2

def test_message_too_large(tmp_path: Path):
    cfg = EngineConfig(
        db_path=tmp_path/"db.sqlite",
        decisions_jsonl=tmp_path/"decisions.jsonl",
        max_message_bytes=10,
    )
    app = create_app(cfg)
    c = TestClient(app)
    r = c.post("/ingest", json={"message": "x" * 50, "source": "mac"})
    assert r.status_code == 413

def test_policy_override_and_report(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "whitelist:\n"
        "  - \"AWS CreateUser user=*\"\n"
        "blacklist:\n"
        "  - \"Healthcheck OK service=*\"\n"
    )
    cfg = EngineConfig(
        db_path=tmp_path/"db.sqlite",
        decisions_jsonl=tmp_path/"decisions.jsonl",
        policy_path=policy_path,
    )
    app = create_app(cfg)
    c = TestClient(app)

    r1 = c.post("/ingest", json={"message": "Healthcheck OK service=api latency_ms=10", "source":"mac"})
    assert r1.status_code == 200
    assert r1.json().get("policy_overridden") == "blacklist"

    r2 = c.post("/ingest", json={"message": "AWS CreateUser user=admin sourceIp=1.2.3.4", "source":"mac"})
    assert r2.status_code == 200
    assert r2.json().get("policy_overridden") == "whitelist"

    rep = c.get("/policy/report").json()
    assert rep["enabled"] is True
    assert rep["blacklist"] >= 1
    assert rep["whitelist"] >= 1
    assert rep["total"] >= 2

def test_warmup_and_stable_suppression(tmp_path: Path):
    cfg = EngineConfig(
        db_path=tmp_path/"db.sqlite",
        decisions_jsonl=tmp_path/"decisions.jsonl",
        warmup_events_per_template=5,
        warmup_risk_override=30,
        stable_min_age_minutes=0,
        stable_score_threshold=0.0,
        stable_suppress_risk=10,
        stable_min_count=1,
    )
    app = create_app(cfg)
    c = TestClient(app)

    # Warmup should suppress early instances.
    for i in range(4):
        r = c.post("/ingest", json={"message": "Healthcheck OK service=api latency_ms=10", "source":"mac"})
        assert r.status_code == 200
        assert r.json()["decision"] == "suppress"
        assert "warmup_template" in r.json()["reasons"]

    # After warmup, stability should still suppress if low risk.
    r = c.post("/ingest", json={"message": "Healthcheck OK service=api latency_ms=10", "source":"mac"})
    assert r.status_code == 200
    assert r.json()["decision"] == "suppress"
    assert "stable_template" in r.json()["reasons"]
