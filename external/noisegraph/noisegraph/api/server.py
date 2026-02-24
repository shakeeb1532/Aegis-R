from __future__ import annotations
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, List, Iterable, Tuple
import time
import threading
from datetime import datetime

from noisegraph.config import EngineConfig
from noisegraph.storage.sqlite import SQLiteStore
from noisegraph.normalize.parser import parse_raw
from noisegraph.engine.baseline import timebucket_index, update_baseline, adaptive_alpha
from noisegraph.engine.graph import extract_edges, edge_hash
from noisegraph.engine.scorer import score_event
from noisegraph.engine.cluster import incident_id_for
from noisegraph.engine.decisions import decide, explain
from noisegraph.outputs.jsonl import append_jsonl
from noisegraph.utils.cache import LRUCache
from noisegraph.policy import load_policy

class IngestBody(BaseModel):
    message: str
    source: str = "unknown"
    stream: str = "http"

class BatchIngestBody(BaseModel):
    events: List[IngestBody]

def create_app(cfg: EngineConfig) -> FastAPI:
    app = FastAPI(title="noisegraph", version="0.1.0")
    store = SQLiteStore(cfg.db_path)
    policy = load_policy(cfg.policy_path)
    policy_report = {"whitelist": 0, "blacklist": 0, "total": 0}
    policy_lock = threading.Lock()

    # simple in-memory counter per key+bucket (MVP)
    rate_counters: Dict[str, int] = {}
    # caches
    baseline_cache = LRUCache[str, dict](cfg.baseline_cache_size, cfg.baseline_cache_ttl_s)
    edge_cache = LRUCache[str, bool](cfg.edge_cache_size, cfg.edge_cache_ttl_s)

    # template stats for stability scoring
    template_stats: Dict[str, dict] = {}
    stats_lock = threading.Lock()

    # buffered DB writes (background flusher)
    template_buf: List[tuple[str, str]] = []
    edge_buf: List[tuple[str, str, str]] = []
    baseline_buf: List[tuple[str, int, float, float, float, float, str]] = []
    buf_lock = threading.Lock()
    last_flush = time.monotonic()

    def enqueue_template(template: str, ts: str) -> None:
        with buf_lock:
            template_buf.append((template, ts))

    def enqueue_edge(edge_h: str, ts: str) -> None:
        with buf_lock:
            edge_buf.append((edge_h, ts, ts))

    def enqueue_baseline(
        key: str, bucket: int, ewma: float, q50: float, q90: float, q99: float, ts: str
    ) -> None:
        with buf_lock:
            baseline_buf.append((key, bucket, ewma, q50, q90, q99, ts))

    def _parse_ts(ts_iso: str) -> float:
        try:
            return datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).timestamp()
        except Exception:
            return time.time()

    def update_template_stats(template: str, ts_iso: str) -> dict:
        ts = _parse_ts(ts_iso)
        with stats_lock:
            st = template_stats.get(template)
            if st is None:
                st = {"count": 0, "first_ts": ts, "last_ts": ts}
                template_stats[template] = st
            st["count"] += 1
            st["last_ts"] = ts
            return st.copy()

    def stability_score(st: dict) -> float:
        count = st.get("count", 0)
        age_s = max(0.0, st.get("last_ts", 0) - st.get("first_ts", 0))
        age_min = age_s / 60.0
        if count <= 0:
            return 0.0
        count_score = min(1.0, count / max(1, cfg.stable_min_count))
        age_score = min(1.0, age_min / max(1, cfg.stable_min_age_minutes))
        return count_score * age_score

    def flush_buffers(force: bool = False) -> None:
        nonlocal last_flush
        now = time.monotonic()
        with buf_lock:
            total = len(template_buf) + len(edge_buf) + len(baseline_buf)
            if not force:
                if total < cfg.db_flush_events and (now - last_flush) < cfg.db_flush_seconds:
                    return
            t_items = template_buf[:]
            e_items = edge_buf[:]
            b_items = baseline_buf[:]
            template_buf.clear()
            edge_buf.clear()
            baseline_buf.clear()
        if t_items:
            store.bulk_upsert_templates(t_items)
        if e_items:
            store.bulk_upsert_edges(e_items)
        if b_items:
            store.bulk_upsert_baselines(b_items)
        last_flush = now

    def flusher_loop() -> None:
        while True:
            time.sleep(min(0.5, cfg.db_flush_seconds))
            try:
                flush_buffers()
            except Exception:
                # best-effort: avoid crashing the server
                pass

    threading.Thread(target=flusher_loop, daemon=True).start()

    def validate_message(msg: str) -> None:
        if not msg:
            raise HTTPException(status_code=422, detail={"error": "message_required"})
        if len(msg.encode("utf-8")) > cfg.max_message_bytes:
            raise HTTPException(status_code=413, detail={"error": "message_too_large"})

    @app.middleware("http")
    async def limit_body_size(request: Request, call_next):
        body = await request.body()
        if len(body) > cfg.max_body_bytes:
            raise HTTPException(status_code=413, detail={"error": "body_too_large"})
        request._body = body  # type: ignore[attr-defined]
        return await call_next(request)

    @app.get("/health")
    def health() -> dict:
        return {"ok": True}

    def handle_event(body: IngestBody) -> dict:
        validate_message(body.message)
        ev, _ = parse_raw(body.message, source=body.source, stream=body.stream)
        ts = ev["ts"]
        enqueue_template(ev["template"], ts)
        st = update_template_stats(ev["template"], ts)

        ent = ev.get("entity", {}) or {}
        host = ent.get("source") or ev.get("source") or "unknown"
        key = f"{host}|{ev['template']}"
        bucket = timebucket_index(ts, cfg.timebucket_minutes)

        rk = f"{key}|{bucket}"
        rate_counters[rk] = rate_counters.get(rk, 0) + 1
        observed = float(rate_counters[rk])

        bkey = f"{key}|{bucket}"
        prev = baseline_cache.get(bkey)
        if prev is None:
            prev = store.get_baseline(key, bucket)
            if prev is not None:
                baseline_cache.set(bkey, prev)
        prev_ewma = float(prev["ewma"]) if prev else None
        a = adaptive_alpha(cfg.ewma_alpha, prev_ewma, observed, cfg.ewma_alpha_min, cfg.ewma_alpha_max)
        upd = update_baseline(prev, observed_rate=observed, alpha=a)
        baseline_cache.set(bkey, {"ewma": upd.ewma, "q50": upd.q50, "q90": upd.q90, "q99": upd.q99})
        enqueue_baseline(key, bucket, upd.ewma, upd.q50, upd.q90, upd.q99, ts)

        rate_anomaly = (observed > upd.q99) and (upd.ewma > cfg.min_rate_for_anomaly)

        edges = extract_edges(ev)
        edge_hashes = [edge_hash(s, d, k) for s, d, k in edges]
        unknown = {h for h in edge_hashes if not edge_cache.contains(h)}
        existing_db = store.edges_exist(list(unknown)) if unknown else set()
        first_seen = 0
        for h in edge_hashes:
            if h in existing_db:
                edge_cache.set(h, True)
                continue
            if edge_cache.contains(h):
                continue
            if h in unknown:
                first_seen += 1
                edge_cache.set(h, True)
            enqueue_edge(h, ts)

        # crude rarity proxy for MVP
        rare_template = first_seen > 0

        sr = score_event(rate_anomaly=rate_anomaly, first_seen_edges=first_seen, rare_template=rare_template)
        inc_id = incident_id_for(ev, cfg.cluster_window_seconds)

        decision = decide(sr.risk, cfg.escalate_risk, cfg.suppress_risk)
        exp = explain(decision, sr.reasons)

        if st.get("count", 0) < cfg.warmup_events_per_template and sr.risk < cfg.warmup_risk_override:
            decision = "suppress"
            sr.reasons.append("warmup_template")
            exp = explain(decision, sr.reasons)

        stable = stability_score(st)
        if stable >= cfg.stable_score_threshold and sr.risk < cfg.stable_suppress_risk:
            if "stable_template" not in sr.reasons:
                sr.reasons.append("stable_template")
            decision = "suppress"
            exp = explain(decision, sr.reasons)

        policy_overridden = None
        if policy:
            if policy.match_whitelist(ev["template"]):
                if "policy_whitelist" not in sr.reasons:
                    sr.reasons.append("policy_whitelist")
                decision = "keep"
                exp = explain(decision, sr.reasons)
                policy_overridden = "whitelist"
            elif policy.match_blacklist(ev["template"]):
                if "policy_blacklist" not in sr.reasons:
                    sr.reasons.append("policy_blacklist")
                decision = "suppress"
                exp = explain(decision, sr.reasons)
                policy_overridden = "blacklist"

        decision_obj = {
            "ts": ts,
            "decision": decision,
            "risk": int(sr.risk),
            "reasons": sr.reasons,
            "incident_id": inc_id,
            "explain": exp,
            "fingerprint": ev["fingerprint"],
            "event": ev,
            "policy_overridden": policy_overridden,
        }
        if policy_overridden:
            with policy_lock:
                policy_report[policy_overridden] += 1
        with policy_lock:
            policy_report["total"] += 1
        store.insert_decision(decision_obj)
        append_jsonl(cfg.decisions_jsonl, decision_obj)
        return decision_obj

    @app.post("/ingest")
    def ingest(body: IngestBody) -> dict:
        return handle_event(body)

    @app.post("/ingest/batch")
    def ingest_batch(body: BatchIngestBody) -> dict:
        if not body.events:
            raise HTTPException(status_code=422, detail={"error": "events_required"})
        if len(body.events) > cfg.max_batch_events:
            raise HTTPException(status_code=413, detail={"error": "batch_too_large"})
        items = handle_events_batch(body.events)
        flush_buffers(force=True)
        return {"items": items, "count": len(items)}

    @app.get("/decisions")
    def decisions(limit: int = 100) -> dict:
        return {"items": store.list_decisions(limit=limit)}

    def handle_events_batch(events: Iterable[IngestBody]) -> List[dict]:
        parsed: List[Tuple[dict, str]] = []
        for body in events:
            validate_message(body.message)
            ev, _ = parse_raw(body.message, source=body.source, stream=body.stream)
            parsed.append((ev, body.message))

        # Precompute edge existence in bulk
        all_edge_hashes: List[str] = []
        event_edges: List[List[str]] = []
        for ev, _ in parsed:
            edges = extract_edges(ev)
            hashes = [edge_hash(s, d, k) for s, d, k in edges]
            event_edges.append(hashes)
            for h in hashes:
                if not edge_cache.contains(h):
                    all_edge_hashes.append(h)

        existing_db = store.edges_exist(list(set(all_edge_hashes))) if all_edge_hashes else set()
        for h in existing_db:
            edge_cache.set(h, True)

        items: List[dict] = []
        for idx, (ev, _raw) in enumerate(parsed):
            ts = ev["ts"]
            enqueue_template(ev["template"], ts)
            st = update_template_stats(ev["template"], ts)

            ent = ev.get("entity", {}) or {}
            host = ent.get("source") or ev.get("source") or "unknown"
            key = f"{host}|{ev['template']}"
            bucket = timebucket_index(ts, cfg.timebucket_minutes)

            rk = f"{key}|{bucket}"
            rate_counters[rk] = rate_counters.get(rk, 0) + 1
            observed = float(rate_counters[rk])

            bkey = f"{key}|{bucket}"
            prev = baseline_cache.get(bkey)
            if prev is None:
                prev = store.get_baseline(key, bucket)
                if prev is not None:
                    baseline_cache.set(bkey, prev)
            prev_ewma = float(prev["ewma"]) if prev else None
            a = adaptive_alpha(cfg.ewma_alpha, prev_ewma, observed, cfg.ewma_alpha_min, cfg.ewma_alpha_max)
            upd = update_baseline(prev, observed_rate=observed, alpha=a)
            baseline_cache.set(bkey, {"ewma": upd.ewma, "q50": upd.q50, "q90": upd.q90, "q99": upd.q99})
            enqueue_baseline(key, bucket, upd.ewma, upd.q50, upd.q90, upd.q99, ts)

            rate_anomaly = (observed > upd.q99) and (upd.ewma > cfg.min_rate_for_anomaly)

            hashes = event_edges[idx]
            first_seen = 0
            for h in hashes:
                if edge_cache.contains(h):
                    continue
                if h in existing_db:
                    edge_cache.set(h, True)
                    continue
                first_seen += 1
                edge_cache.set(h, True)
                enqueue_edge(h, ts)

            rare_template = first_seen > 0

            sr = score_event(rate_anomaly=rate_anomaly, first_seen_edges=first_seen, rare_template=rare_template)
            inc_id = incident_id_for(ev, cfg.cluster_window_seconds)

            decision = decide(sr.risk, cfg.escalate_risk, cfg.suppress_risk)
            exp = explain(decision, sr.reasons)

            if st.get("count", 0) < cfg.warmup_events_per_template and sr.risk < cfg.warmup_risk_override:
                decision = "suppress"
                sr.reasons.append("warmup_template")
                exp = explain(decision, sr.reasons)

            stable = stability_score(st)
            if stable >= cfg.stable_score_threshold and sr.risk < cfg.stable_suppress_risk:
                if "stable_template" not in sr.reasons:
                    sr.reasons.append("stable_template")
                decision = "suppress"
                exp = explain(decision, sr.reasons)

            policy_overridden = None
            if policy:
                if policy.match_whitelist(ev["template"]):
                    if "policy_whitelist" not in sr.reasons:
                        sr.reasons.append("policy_whitelist")
                    decision = "keep"
                    exp = explain(decision, sr.reasons)
                    policy_overridden = "whitelist"
                elif policy.match_blacklist(ev["template"]):
                    if "policy_blacklist" not in sr.reasons:
                        sr.reasons.append("policy_blacklist")
                    decision = "suppress"
                    exp = explain(decision, sr.reasons)
                    policy_overridden = "blacklist"

            decision_obj = {
                "ts": ts,
                "decision": decision,
                "risk": int(sr.risk),
                "reasons": sr.reasons,
                "incident_id": inc_id,
                "explain": exp,
                "fingerprint": ev["fingerprint"],
                "event": ev,
                "policy_overridden": policy_overridden,
            }
            if policy_overridden:
                with policy_lock:
                    policy_report[policy_overridden] += 1
            with policy_lock:
                policy_report["total"] += 1
            store.insert_decision(decision_obj)
            append_jsonl(cfg.decisions_jsonl, decision_obj)
            items.append(decision_obj)
        return items

    @app.get("/policy/report")
    def policy_report_endpoint() -> dict:
        if not policy:
            return {"enabled": False, "whitelist": 0, "blacklist": 0, "total": 0}
        with policy_lock:
            return {"enabled": True, **policy_report}

    return app
