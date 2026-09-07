"""Persistence for incident triage state (Open / Acknowledged / False
Positive / Confirmed).

Now a thin HTTP client for api/routes/triage.py's tenant-scoped,
Postgres-backed endpoints -- not a local SQLite file. That file was
never actually shared beyond one machine (a dashboard pod and an
analyst's own laptop running terminal/tsoc_console.py each had their
own, defeating the whole point), and its "actor" was a free-text string
nothing cross-checked against who was actually authenticated.

Every function takes the caller's own bearer token (a per-employee JWT
from api/routes/auth.py's login) since that is what identifies both
*which tenant* and *who is acting* -- there is no longer a single
shared credential this module can hold on its own behalf the way
TRIAGE_DB_PATH once let it.
"""
import os

import requests

OPEN = "open"
ACKNOWLEDGED = "acknowledged"
FALSE_POSITIVE = "false_positive"
CONFIRMED = "confirmed"

VALID_STATUSES = {OPEN, ACKNOWLEDGED, FALSE_POSITIVE, CONFIRMED}

# Same env var shared/data_access.py already reads for the same backend --
# one source of truth for where the API lives, not a second, independently
# configured URL that could silently drift from it.
_API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1")

_REQUEST_TIMEOUT_SEC = 5


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def set_status(token: str, incident_id: str, status: str, note: str = "") -> dict:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid triage status: {status!r}")
    resp = requests.post(
        f"{_API_URL}/triage/{incident_id}",
        json={"status": status, "note": note},
        headers=_headers(token),
        timeout=_REQUEST_TIMEOUT_SEC,
    )
    resp.raise_for_status()
    return resp.json()


def get_status(token: str, incident_id: str) -> dict:
    resp = requests.get(f"{_API_URL}/triage/{incident_id}", headers=_headers(token), timeout=_REQUEST_TIMEOUT_SEC)
    resp.raise_for_status()
    return resp.json()


def get_all_statuses(token: str) -> dict:
    """Bulk read for rendering a whole incident queue without one query
    per row."""
    resp = requests.get(f"{_API_URL}/triage", headers=_headers(token), timeout=_REQUEST_TIMEOUT_SEC)
    resp.raise_for_status()
    return resp.json()
