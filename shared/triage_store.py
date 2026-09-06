"""Persistence for incident triage state (Open / Acknowledged / False
Positive / Confirmed).

dashboard/'s incidents are synthesized client-side from raw alerts
(DataStreamManager.get_incidents()) rather than read from a database
table, so there was previously nowhere to persist "an analyst
acknowledged this" -- the Analyst Actions buttons clicked and did
nothing, visible to no one, not even the same analyst on their next
page load.

Backed by SQLite (stdlib, no new dependency) rather than
st.session_state so it (a) survives a dashboard process restart and
(b) is shared across every analyst hitting the same dashboard --
session state is per-browser-tab, which would mean two analysts
looking at the same incident queue would each see it as untouched by
the other.
"""
import os
import sqlite3
import threading
from datetime import datetime, timezone

OPEN = "open"
ACKNOWLEDGED = "acknowledged"
FALSE_POSITIVE = "false_positive"
CONFIRMED = "confirmed"

VALID_STATUSES = {OPEN, ACKNOWLEDGED, FALSE_POSITIVE, CONFIRMED}

_DB_PATH = os.getenv(
    "TRIAGE_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "triage.db"),
)
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(_DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_triage (
            incident_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            note TEXT,
            actor TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    return conn


def set_status(incident_id: str, status: str, actor: str = "", note: str = "") -> dict:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid triage status: {status!r}")
    updated_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO incident_triage (incident_id, status, note, actor, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status = excluded.status,
                    note = excluded.note,
                    actor = excluded.actor,
                    updated_at = excluded.updated_at
                """,
                (incident_id, status, note, actor, updated_at),
            )
            conn.commit()
        finally:
            conn.close()
    return {"status": status, "note": note, "actor": actor, "updated_at": updated_at}


def get_status(incident_id: str) -> dict:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT status, note, actor, updated_at FROM incident_triage WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return {"status": OPEN, "note": "", "actor": "", "updated_at": ""}
    return {"status": row[0], "note": row[1] or "", "actor": row[2] or "", "updated_at": row[3]}


def get_all_statuses() -> dict:
    """Bulk read for rendering a whole incident queue without one query
    per row."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT incident_id, status, note, actor, updated_at FROM incident_triage"
            ).fetchall()
        finally:
            conn.close()
    return {
        r[0]: {"status": r[1], "note": r[2] or "", "actor": r[3] or "", "updated_at": r[4]}
        for r in rows
    }
