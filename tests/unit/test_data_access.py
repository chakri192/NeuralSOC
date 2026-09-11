"""shared/data_access.py had 0% direct test coverage despite carrying a
High-severity fix: a module-level `raise RuntimeError` on missing
API_URL/TSOC_API_KEY meant importing this module -- including from
`make dashboard`, which sets neither var -- crashed before a single
Streamlit component rendered. These tests exercise the fix directly:
config loading is lazy and never raises past _init_state(), regardless
of what's configured.
"""
from unittest.mock import patch, MagicMock

import pytest
import requests

from shared.data_access import DataStreamManager, ConfigError, _load_config


@pytest.fixture(autouse=True)
def _reset_singleton():
    """DataStreamManager caches its one instance on the class; without
    resetting it, whichever test runs first would decide every other
    test's config."""
    DataStreamManager._instance = None
    yield
    DataStreamManager._instance = None


def test_load_config_defaults_to_loopback_http_when_unset(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.setenv("TSOC_API_KEY", "k")
    api_url, api_key = _load_config()
    assert api_url == "http://127.0.0.1:8000/api/v1"
    assert api_key == "k"


def test_load_config_rejects_non_https_when_explicitly_set(monkeypatch):
    monkeypatch.setenv("API_URL", "http://example.com/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    with pytest.raises(ConfigError, match="HTTPS"):
        _load_config()


def test_load_config_accepts_https(monkeypatch):
    monkeypatch.setenv("API_URL", "https://api.tsoc.local/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    api_url, api_key = _load_config()
    assert api_url == "https://api.tsoc.local/api/v1"


def test_load_config_requires_api_key(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("TSOC_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="TSOC_API_KEY"):
        _load_config()


def test_init_state_never_raises_on_missing_config(monkeypatch):
    """The regression test for the actual bug: constructing
    DataStreamManager() with no env vars configured at all must not raise
    -- it previously crashed the whole Streamlit process at import time."""
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("TSOC_API_KEY", raising=False)
    mgr = DataStreamManager()  # must not raise
    assert mgr.config_error is not None
    assert "TSOC_API_KEY" in mgr.config_error
    assert mgr.broker_healthy is False


def test_start_listeners_is_a_noop_when_misconfigured(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("TSOC_API_KEY", raising=False)
    mgr = DataStreamManager()
    mgr.start_listeners()
    # No poller thread should have started against a URL/key that don't exist.
    assert mgr.is_running is False


def test_poll_api_marks_unhealthy_on_non_200(monkeypatch):
    monkeypatch.setenv("API_URL", "https://api.tsoc.local/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    mgr = DataStreamManager()
    mgr.broker_healthy = True  # simulate a previously-healthy poll
    mgr.is_running = True

    fake_response = MagicMock(status_code=401)

    def _stop_after_one_iteration(*a, **kw):
        mgr.is_running = False
        return fake_response

    with patch.object(mgr.session, "get", side_effect=_stop_after_one_iteration), \
         patch("shared.data_access.time.sleep"):
        mgr._poll_api()

    # A non-200 response must not leave a stale "healthy" reading.
    assert mgr.broker_healthy is False


def _configured_manager(monkeypatch):
    monkeypatch.setenv("API_URL", "https://api.tsoc.local/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    return DataStreamManager()


def test_poll_api_updates_alerts_and_stats_on_success(monkeypatch):
    mgr = _configured_manager(monkeypatch)
    mgr.is_running = True

    alerts_resp = MagicMock(status_code=200)
    alerts_resp.json.return_value = [{"alert_id": "a1", "source_ip": "10.0.0.1"}]
    stats_resp = MagicMock(status_code=200)
    stats_resp.json.return_value = {"total_alerts": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}

    calls = {"n": 0}

    def fake_get(url, timeout=3):
        calls["n"] += 1
        if calls["n"] >= 2:
            mgr.is_running = False
        return alerts_resp if "/alerts" in url else stats_resp

    with patch.object(mgr.session, "get", side_effect=fake_get), \
         patch("shared.data_access.time.sleep"):
        mgr._poll_api()

    assert mgr.alerts == [{"alert_id": "a1", "source_ip": "10.0.0.1"}]
    assert mgr.stats["high"] == 1
    assert mgr.broker_healthy is True
    assert mgr.last_event_time > 0


def test_poll_api_survives_a_connection_exception(monkeypatch):
    mgr = _configured_manager(monkeypatch)
    mgr.broker_healthy = True
    mgr.is_running = True

    def _raise_then_stop(*a, **kw):
        mgr.is_running = False
        raise ConnectionError("broker unreachable")

    with patch.object(mgr.session, "get", side_effect=_raise_then_stop), \
         patch("shared.data_access.time.sleep"):
        mgr._poll_api()  # must not raise

    assert mgr.broker_healthy is False


def test_start_listeners_starts_a_background_thread_when_configured(monkeypatch):
    mgr = _configured_manager(monkeypatch)
    with patch.object(mgr, "_poll_api"):
        mgr.start_listeners()
        assert mgr.is_running is True


def test_start_listeners_is_idempotent_when_already_running(monkeypatch):
    mgr = _configured_manager(monkeypatch)
    with patch.object(mgr, "_poll_api"), patch("shared.data_access.threading.Thread") as thread_cls:
        mgr.start_listeners()
        mgr.start_listeners()
        # The already-running guard must prevent a second thread from ever
        # being constructed, not just from being started twice.
        assert thread_cls.call_count == 1


class TestGetIncidents:
    def test_empty_alerts_returns_empty_list(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = []
        assert mgr.get_incidents() == []

    def test_alerts_from_same_source_ip_aggregate_into_one_incident(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = [
            {"alert_id": "a1", "source_ip": "10.0.0.5", "destination_ip": "1.1.1.1",
             "threat_class": "DDoS", "severity": "low"},
            {"alert_id": "a2", "source_ip": "10.0.0.5", "destination_ip": "2.2.2.2",
             "threat_class": "Reconnaissance", "severity": "critical"},
        ]
        incidents = mgr.get_incidents()
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc["incident_id"] == "INC-10-0-0-5"
        # Severity must escalate to the highest-scored alert seen, not stay at the first.
        assert inc["severity"] == "critical"
        assert set(inc["threat_classes"]) == {"DDoS", "Reconnaissance"}
        assert set(inc["affected_entities"]) == {"10.0.0.5", "1.1.1.1", "2.2.2.2"}
        assert inc["related_alert_ids"] == ["a1", "a2"]
        # inference.risk.calculate_risk_score(): two distinct detectors
        # (DDoS at severity-implied 0.55, Reconnaissance at 0.97, neither
        # alert sets confidence_score) combine via log-odds pooling, not
        # a flat severity-bucket-plus-volume formula -- see
        # inference/risk.py's docstring for why.
        assert inc["risk_score"] == 97.53

    def test_alerts_from_different_source_ips_produce_separate_incidents(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = [
            {"alert_id": "a1", "source_ip": "10.0.0.1", "severity": "high"},
            {"alert_id": "a2", "source_ip": "10.0.0.2", "severity": "medium"},
        ]
        incidents = mgr.get_incidents()
        assert {i["incident_id"] for i in incidents} == {"INC-10-0-0-1", "INC-10-0-0-2"}

    def test_missing_optional_fields_use_safe_defaults(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = [{}]  # no source_ip, threat_class, destination_ip, alert_id
        incidents = mgr.get_incidents()
        assert len(incidents) == 1
        assert incidents[0]["threat_classes"] == ["Unclassified Threat"]
        assert incidents[0]["affected_entities"] == ["127.0.0.1"]


class TestGetAlerts:
    def test_string_evidence_is_deserialized_to_a_dict(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = [{"alert_id": "a1", "evidence": '{"domain": "bad.example"}'}]
        alerts = mgr.get_alerts()
        assert alerts[0]["evidence"] == {"domain": "bad.example"}

    def test_malformed_evidence_json_falls_back_to_the_raw_string(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = [{"alert_id": "a1", "evidence": "not valid json"}]
        alerts = mgr.get_alerts()  # must not raise
        assert alerts[0]["evidence"] == "not valid json"

    def test_dict_evidence_passes_through_unchanged(self, monkeypatch):
        mgr = _configured_manager(monkeypatch)
        mgr.alerts = [{"alert_id": "a1", "evidence": {"already": "a dict"}}]
        alerts = mgr.get_alerts()
        assert alerts[0]["evidence"] == {"already": "a dict"}


def test_status_reports_health_and_counts(monkeypatch):
    mgr = _configured_manager(monkeypatch)
    mgr.alerts = [{"alert_id": "a1"}, {"alert_id": "a2"}]
    mgr.broker_healthy = True
    mgr.last_event_time = 123.0
    mgr.stats = {"total_alerts": 2}

    result = mgr.status()
    assert result == {
        "broker_healthy": True,
        "last_event_time": 123.0,
        "incident_count": 2,
        "alert_count": 2,
        "stats": {"total_alerts": 2},
    }


class TestFetchAlerts:
    """fetch_alerts()/fetch_stats() are the tenant-scoped (per-employee
    JWT) alternative to DataStreamManager's single-TSOC_API_KEY polling
    above -- used by terminal/tsoc_console.py and dashboard/session_data.py,
    neither of which can share one process-wide, all-tenant credential.
    Same mocking style as tests/unit/test_triage_store.py, which already
    covers this exact HTTP-client shape.
    """

    def _mock_response(self, json_body, status_code=200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_body
        if status_code >= 400:
            resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
        else:
            resp.raise_for_status.side_effect = None
        return resp

    def test_fetch_alerts_gets_the_right_url_headers_and_params(self, monkeypatch):
        from shared import data_access

        with patch(
            "shared.data_access.requests.get",
            return_value=self._mock_response([{"alert_id": "a1", "evidence": "{}"}]),
        ) as mock_get:
            result = data_access.fetch_alerts("my-jwt", limit=50)

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        assert args[0] == f"{data_access._API_URL}/alerts"
        assert kwargs["params"] == {"limit": 50}
        assert kwargs["headers"] == {"Authorization": "Bearer my-jwt"}
        assert result == [{"alert_id": "a1", "evidence": {}}]

    def test_fetch_alerts_deserializes_string_evidence(self, monkeypatch):
        from shared import data_access

        with patch(
            "shared.data_access.requests.get",
            return_value=self._mock_response([{"alert_id": "a1", "evidence": '{"domain": "bad.example"}'}]),
        ):
            result = data_access.fetch_alerts("tok")
        assert result[0]["evidence"] == {"domain": "bad.example"}

    def test_fetch_alerts_raises_on_an_http_error(self, monkeypatch):
        from shared import data_access

        with patch("shared.data_access.requests.get", return_value=self._mock_response({"detail": "nope"}, status_code=401)):
            with pytest.raises(requests.HTTPError):
                data_access.fetch_alerts("tok")

    def test_fetch_stats_gets_the_right_url_and_headers(self, monkeypatch):
        from shared import data_access

        stats = {"total_alerts": 3, "critical": 1, "high": 0, "medium": 1, "low": 1}
        with patch("shared.data_access.requests.get", return_value=self._mock_response(stats)) as mock_get:
            result = data_access.fetch_stats("my-jwt")

        args, kwargs = mock_get.call_args
        assert args[0] == f"{data_access._API_URL}/stats"
        assert kwargs["headers"] == {"Authorization": "Bearer my-jwt"}
        assert result == stats

    def test_fetch_stats_raises_on_a_network_error(self, monkeypatch):
        from shared import data_access

        with patch("shared.data_access.requests.get", side_effect=requests.ConnectionError("unreachable")):
            with pytest.raises(requests.ConnectionError):
                data_access.fetch_stats("tok")
