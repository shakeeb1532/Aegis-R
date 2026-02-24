from __future__ import annotations
import sqlite3
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import threading

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS templates (
  template TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER
);

CREATE TABLE IF NOT EXISTS baselines (
  key TEXT,
  timebucket INTEGER,
  ewma REAL,
  q50 REAL,
  q90 REAL,
  q99 REAL,
  last_updated TEXT,
  PRIMARY KEY (key, timebucket)
);

CREATE TABLE IF NOT EXISTS seen_edges (
  edge_hash TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER
);

CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT,
  fingerprint TEXT,
  decision TEXT,
  risk INTEGER,
  reasons TEXT,
  incident_id TEXT,
  explain TEXT,
  payload_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS idx_decisions_inc ON decisions(incident_id);
"""

class SQLiteStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.executescript(SCHEMA)
            self.conn.commit()

    def upsert_template(self, template: str, ts: str) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO templates(template, first_seen, last_seen, count)
                VALUES(?,?,?,1)
                ON CONFLICT(template) DO UPDATE SET
                  last_seen=excluded.last_seen,
                  count=count+1
                """,
                (template, ts, ts),
            )
            self.conn.commit()

    def get_baseline(self, key: str, timebucket: int) -> Optional[dict]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM baselines WHERE key=? AND timebucket=?", (key, timebucket))
            row = cur.fetchone()
            return dict(row) if row else None

    def upsert_baseline(self, key: str, timebucket: int, ewma: float, q50: float, q90: float, q99: float, ts: str) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO baselines(key, timebucket, ewma, q50, q90, q99, last_updated)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(key,timebucket) DO UPDATE SET
                  ewma=excluded.ewma,
                  q50=excluded.q50,
                  q90=excluded.q90,
                  q99=excluded.q99,
                  last_updated=excluded.last_updated
                """,
                (key, timebucket, ewma, q50, q90, q99, ts),
            )
            self.conn.commit()

    def upsert_edge(self, edge_hash: str, ts: str) -> bool:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT 1 FROM seen_edges WHERE edge_hash=?", (edge_hash,))
            row = cur.fetchone()
            cur.execute(
                """
                INSERT INTO seen_edges(edge_hash, first_seen, last_seen, count)
                VALUES(?,?,?,1)
                ON CONFLICT(edge_hash) DO UPDATE SET
                  last_seen=excluded.last_seen,
                  count=count+1
                """,
                (edge_hash, ts, ts),
            )
            self.conn.commit()
            return row is None

    def insert_decision(self, d: Dict[str, Any]) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO decisions(ts, fingerprint, decision, risk, reasons, incident_id, explain, payload_json)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    d["ts"],
                    d["fingerprint"],
                    d["decision"],
                    int(d["risk"]),
                    json.dumps(d.get("reasons", [])),
                    d["incident_id"],
                    d.get("explain", ""),
                    json.dumps(d),
                ),
            )
            self.conn.commit()

    def list_decisions(self, limit: int = 100) -> List[dict]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT payload_json FROM decisions ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [json.loads(r["payload_json"]) for r in rows]

    def bulk_upsert_templates(self, items: List[tuple[str, str]]) -> None:
        if not items:
            return
        with self._lock:
            cur = self.conn.cursor()
            cur.executemany(
                """
                INSERT INTO templates(template, first_seen, last_seen, count)
                VALUES(?,?,?,1)
                ON CONFLICT(template) DO UPDATE SET
                  last_seen=excluded.last_seen,
                  count=count+1
                """,
                [(t, ts, ts) for t, ts in items],
            )
            self.conn.commit()

    def bulk_upsert_edges(self, items: List[tuple[str, str, str]]) -> int:
        if not items:
            return 0
        # items: (edge_hash, first_seen, last_seen)
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT edge_hash FROM seen_edges WHERE edge_hash IN (%s)" % ",".join("?" * len(items)),
                [h for h, _fs, _ls in items],
            )
            existing = {r["edge_hash"] for r in cur.fetchall()}
            cur.executemany(
                """
                INSERT INTO seen_edges(edge_hash, first_seen, last_seen, count)
                VALUES(?,?,?,1)
                ON CONFLICT(edge_hash) DO UPDATE SET
                  last_seen=excluded.last_seen,
                  count=count+1
                """,
                items,
            )
            self.conn.commit()
            return len([h for h, _fs, _ls in items if h not in existing])

    def edges_exist(self, hashes: List[str]) -> set[str]:
        if not hashes:
            return set()
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT edge_hash FROM seen_edges WHERE edge_hash IN (%s)" % ",".join("?" * len(hashes)),
                hashes,
            )
            return {r["edge_hash"] for r in cur.fetchall()}

    def bulk_upsert_baselines(
        self, items: List[tuple[str, int, float, float, float, float, str]]
    ) -> None:
        if not items:
            return
        with self._lock:
            cur = self.conn.cursor()
            cur.executemany(
                """
                INSERT INTO baselines(key, timebucket, ewma, q50, q90, q99, last_updated)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(key,timebucket) DO UPDATE SET
                  ewma=excluded.ewma,
                  q50=excluded.q50,
                  q90=excluded.q90,
                  q99=excluded.q99,
                  last_updated=excluded.last_updated
                """,
                items,
            )
            self.conn.commit()
