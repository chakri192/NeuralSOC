"""
Centralized Data Access Layer.
Fetches data from the enterprise FastAPI Backend instead of Kafka directly.
This allows historical persistence and decouples the UI from the message broker.
"""
import os
import json
import requests
import threading
import time
import logging
from datetime import datetime, timezone

from inference.risk import calculate_risk_score

logger = logging.getLogger("data_access")

# Only for picking which single severity string to display as an
# incident's headline "severity" field (the highest-scored alert's own
# severity wins) -- risk SCORING itself is calculate_risk_score() above,
# not this table.
_SEVERITY_DISPLAY_ORDER = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}

# Same env var _load_config() resolves below for DataStreamManager, and
# the same one shared/triage_store.py and terminal/tsoc_console.py each
# read independently -- one source of truth for where the API lives.
_API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1")
_REQUEST_TIMEOUT_SEC = 5


class ConfigError(RuntimeError):
    """Raised by _load_config() when required dashboard config (API_URL,
    TSOC_API_KEY) is missing or invalid. Deliberately NOT raised at import
    time or from DataStreamManager.__new__ -- this module used to raise a
    bare RuntimeError at import, which meant simply importing it (as any
    test, or the dashboard itself under Makefile's `dashboard` target,
    which sets neither env var) crashed before a single Streamlit
    component rendered. _init_state() now catches this and stores it on
    the instance; the dashboard shows the existing "pipeline unavailable"
    empty state instead of crashing outright."""


def _load_config():
    api_url = os.getenv("API_URL")
    if api_url is None:
        api_url = "http://127.0.0.1:8000/api/v1"  # local dev default (loopback only)
    elif not api_url.startswith("https://"):
        raise ConfigError("API_URL must use HTTPS when explicitly set")

    api_key = os.environ.get("TSOC_API_KEY", "")
    if not api_key:
        raise ConfigError("TSOC_API_KEY not set")

    return api_url, api_key


def synthesize_incidents(alerts: list) -> list:
    """Synthesizes structured Incident objects from a list of raw alerts.
    Enforces schema conformity to prevent KeyError in UI pages.

    A free function (not a DataStreamManager method) so a caller with its
    own, differently-sourced alert list -- terminal/tsoc_console.py reads
    tenant-scoped alerts via its own per-employee JWT, not through this
    module's single-service-key singleton -- can reuse the exact same
    grouping/risk-scoring logic instead of re-implementing it.

    Risk scoring itself is inference.risk.calculate_risk_score() -- this
    function used to reimplement a materially weaker version inline
    (uncapped severity-bucket max + a flat volume bonus, ignoring each
    alert's own confidence_score entirely), a second implementation that
    had already drifted from the live pipeline's own scoring before this
    was noticed. Same real alert schema either way (confidence_score,
    model_name, from api/routes/alerts.py's stored rows), so the shared
    function applies directly.
    """
    if not alerts:
        return []

    incidents_by_src = {}

    for a in alerts:
        src = a.get("source_ip") or "127.0.0.1"
        if src not in incidents_by_src:
            incidents_by_src[src] = {
                "incident_id": f"INC-{src.replace('.', '-')}",
                "created_timestamp": a.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "severity": a.get("severity", "low"),
                "threat_classes": set(),
                "affected_entities": set([src, a.get("destination_ip", "")]),
                "related_alert_ids": [],
                "evidence_summary": "",
                "status": "active",
                "max_sev_score": 0.0,
                "group_alerts": [],
            }
        inc = incidents_by_src[src]
        inc["group_alerts"].append(a)
        if a.get("threat_class"):
            inc["threat_classes"].add(a["threat_class"])
        if a.get("destination_ip"):
            inc["affected_entities"].add(a["destination_ip"])
        if a.get("alert_id"):
            inc["related_alert_ids"].append(a["alert_id"])

        sev = str(a.get("severity", "low")).lower()
        score = _SEVERITY_DISPLAY_ORDER.get(sev, 25.0)
        if score > inc["max_sev_score"]:
            inc["max_sev_score"] = score
            inc["severity"] = sev

    formatted_incidents = []
    for src, inc in incidents_by_src.items():
        risk_score = calculate_risk_score(inc["group_alerts"])

        threats = list(inc["threat_classes"]) if inc["threat_classes"] else ["Unclassified Threat"]
        entities = [e for e in inc["affected_entities"] if e]

        formatted_incidents.append({
            "incident_id": inc["incident_id"],
            "created_timestamp": inc["created_timestamp"],
            "severity": inc["severity"],
            "risk_score": float(risk_score),
            "threat_classes": threats,
            "affected_entities": entities if entities else [src],
            "related_alert_ids": inc["related_alert_ids"],
            "evidence_summary": f"Aggregated {len(inc['group_alerts'])} alert(s) across {len(threats)} threat class(es) involving {src}",
            "status": "active",
            "mitre_tactics": ["Command and Control", "Initial Access"],
            "mitre_techniques": ["T1071", "T1132"]
        })

    return formatted_incidents


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _deserialize_evidence(alerts: list) -> list:
    """api/schemas.py's AlertResponse sends `evidence` as a JSON string
    (matching api/models.py's underlying Text column) -- callers that
    render it (dashboard/components/ui.py's render_evidence_columns,
    shared/formatters.categorize_evidence) expect a dict, not a string,
    so every raw fetch needs this same normalization applied once."""
    for item in alerts:
        if isinstance(item.get("evidence"), str):
            try:
                item["evidence"] = json.loads(item["evidence"])
            except Exception as ex:
                logger.debug("Evidence deserialization fallback: %s", ex)
    return alerts


def fetch_alerts(token: str, limit: int = 100) -> list:
    """Tenant-scoped alert fetch using the caller's own per-employee JWT --
    the API's /alerts endpoint already filters by that token's tenant_id
    (api/deps.py's scope_to_tenant), so there is no separate, client-side
    tenant filter to apply here. This is the shared implementation behind
    both terminal/tsoc_console.py's incident queue and the web dashboard's
    per-session reads (dashboard/session_data.py) -- neither can go
    through DataStreamManager below, which authenticates with the single,
    all-tenant TSOC_API_KEY rather than a per-employee token.
    """
    resp = requests.get(
        f"{_API_URL}/alerts",
        params={"limit": limit},
        headers=_headers(token),
        timeout=_REQUEST_TIMEOUT_SEC,
    )
    resp.raise_for_status()
    return _deserialize_evidence(resp.json())


def fetch_stats(token: str) -> dict:
    """Tenant-scoped severity counts -- see fetch_alerts()'s docstring."""
    resp = requests.get(f"{_API_URL}/stats", headers=_headers(token), timeout=_REQUEST_TIMEOUT_SEC)
    resp.raise_for_status()
    return resp.json()


class DataStreamManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DataStreamManager, cls).__new__(cls)
                cls._instance._init_state()
            return cls._instance

    def _init_state(self):
        self.alerts = []
        self.stats = {"total_alerts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

        self.is_running = False
        self.broker_healthy = False
        self.last_event_time = 0.0
        self.config_error = None
        self.api_url = None

        api_key = None
        try:
            self.api_url, api_key = _load_config()
        except ConfigError as e:
            self.config_error = str(e)
            logger.error("[DataAccess] Configuration error: %s", e)

        self.session = requests.Session()
        if api_key:
            self.session.headers.update({
                "Authorization": f"Bearer {api_key}",
            })

    def start_listeners(self):
        logging.basicConfig(level=logging.INFO)
        if self.config_error:
            # Nothing to poll; broker_healthy stays False and the dashboard
            # renders its existing "pipeline unavailable" state rather than
            # this thread starting against a URL/key that don't exist.
            return
        with self._lock:
            if self.is_running:
                return
            self.is_running = True

        threading.Thread(target=self._poll_api, daemon=True).start()

    def _poll_api(self):
        while self.is_running:
            try:
                # Short timeouts; do not block indefinitely.
                # limit=100 matches the API's server-side cap (Query(..., le=100));
                # requesting 200 here used to get a 422 on every single poll.
                resp_alerts = self.session.get(f"{self.api_url}/alerts?limit=100", timeout=3)
                if resp_alerts.status_code == 200:
                    data = resp_alerts.json()
                    if isinstance(data, list):
                        self.alerts = data
                        self.broker_healthy = True
                        self.last_event_time = time.time()
                else:
                    # A non-2xx response (401, 422, 500, ...) doesn't raise
                    # in `requests`, so without this branch broker_healthy
                    # could silently stay at whatever it last was -- a
                    # stale "healthy" reading against a backend that is
                    # actually rejecting every request.
                    self.broker_healthy = False
                    logger.warning("[DataAccess] /alerts returned %s", resp_alerts.status_code)

                resp_stats = self.session.get(f"{self.api_url}/stats", timeout=3)
                if resp_stats.status_code == 200:
                    stats_data = resp_stats.json()
                    if isinstance(stats_data, dict):
                        self.stats = stats_data
            except Exception as e:
                self.broker_healthy = False
                logger.error("[DataAccess] Failed to connect to API: %s", e)
            # Cap polling rate to avoid thread starvation
            time.sleep(2)

    def get_incidents(self) -> list:
        return synthesize_incidents(self.alerts)

    def get_alerts(self) -> list:
        return _deserialize_evidence([dict(a) for a in self.alerts])

    def status(self) -> dict:
        return {
            "broker_healthy": self.broker_healthy,
            "last_event_time": self.last_event_time,
            "incident_count": len(self.alerts),
            "alert_count": len(self.alerts),
            "stats": self.stats
        }


# Global singleton accessor
stream_manager = DataStreamManager()
