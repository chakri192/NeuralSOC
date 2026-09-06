"""inference/correlation.py sat at 60% coverage: check_redis_master()'s real
body, the SSL/TLS connection-pool branch, add_alert()'s input-validation
edge cases, and rollback_alert_seen()'s error paths were only ever
exercised through a patched check_redis_master() or the happy path, never
directly. These tests exercise each of those branches directly against a
real (fakeredis-backed) IncidentCorrelator, using a unique source_ip per
test to avoid any cross-test Redis-state bleed through fakeredis's shared
default in-memory server.
"""
import os
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
import redis as redis_module

os.environ.setdefault("REDIS_PASSWORD", "test-only-redis-password-do-not-use-in-prod")
os.environ.setdefault("REDIS_SSL", "false")

from inference.correlation import IncidentCorrelator  # noqa: E402

# tests/conftest.py's session-scoped autouse fixture patches
# IncidentCorrelator.check_redis_master to always return True for the
# whole test session (so merely importing inference.stream_processor_faust
# elsewhere doesn't need a live Redis) -- captured here, at module
# collection time, before that fixture's first `.start()` call, so
# TestCheckRedisMaster can invoke the genuine unpatched implementation
# directly instead of whatever the class attribute currently points to.
_REAL_CHECK_REDIS_MASTER = IncidentCorrelator.check_redis_master


def _make_correlator():
    fake = fakeredis.FakeStrictRedis(decode_responses=True, server=fakeredis.FakeServer())
    with patch("inference.correlation.redis.Redis", return_value=fake), \
         patch.object(IncidentCorrelator, "check_redis_master", return_value=True):
        correlator = IncidentCorrelator()
    # Bind an instance-level override (rather than relying on the class-level
    # patch above, which is already closed by the time this returns) so
    # every later add_alert()/rollback_alert_seen() call on this specific
    # instance skips the real check_redis_master() -- which fakeredis can't
    # satisfy (no INFO command support) -- regardless of whether some other
    # global patch happens to still be active.
    correlator.check_redis_master = lambda: True
    return correlator


def test_missing_redis_password_raises_at_construction(monkeypatch):
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="REDIS_PASSWORD"):
        with patch("inference.correlation.redis.Redis", return_value=MagicMock()):
            IncidentCorrelator()


class TestSslConnectionSetup:
    def test_ssl_enabled_with_explicit_ca_cert_path(self, monkeypatch, tmp_path):
        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("fake-ca-cert")
        monkeypatch.setenv("REDIS_SSL", "true")
        monkeypatch.setenv("REDIS_CA_CERT_PATH", str(ca_file))
        fake_client = MagicMock()
        with patch("inference.correlation.redis.Redis", return_value=fake_client):
            correlator = IncidentCorrelator()
        fake_client.ping.assert_called_once()
        assert correlator.redis is fake_client

    def test_ssl_enabled_without_ca_cert_path_falls_back_to_certifi(self, monkeypatch):
        monkeypatch.setenv("REDIS_SSL", "true")
        monkeypatch.delenv("REDIS_CA_CERT_PATH", raising=False)
        fake_client = MagicMock()
        with patch("inference.correlation.redis.Redis", return_value=fake_client):
            IncidentCorrelator()  # must not raise
        fake_client.ping.assert_called_once()


class TestCheckRedisMaster:
    """Calls _REAL_CHECK_REDIS_MASTER(correlator) directly -- an unbound
    function reference captured before conftest.py's session-scoped
    autouse fixture patches the class attribute -- rather than
    correlator.check_redis_master(), which would just invoke that
    session-wide mock regardless of what's patched here."""

    def test_returns_true_when_role_is_master(self):
        correlator = _make_correlator()
        correlator._last_master_check = 0
        with patch.object(correlator.redis, "info", return_value={"role": "master"}):
            assert _REAL_CHECK_REDIS_MASTER(correlator) is True

    def test_returns_false_when_role_is_not_master(self):
        correlator = _make_correlator()
        correlator._last_master_check = 0
        with patch.object(correlator.redis, "info", return_value={"role": "slave"}):
            assert _REAL_CHECK_REDIS_MASTER(correlator) is False

    def test_returns_false_on_redis_error_without_raising(self):
        correlator = _make_correlator()
        correlator._last_master_check = 0
        with patch.object(correlator.redis, "info", side_effect=redis_module.ConnectionError("down")):
            assert _REAL_CHECK_REDIS_MASTER(correlator) is False

    def test_result_is_cached_within_the_check_interval(self):
        correlator = _make_correlator()
        correlator._last_master_check = 0
        info_mock = MagicMock(return_value={"role": "master"})
        with patch.object(correlator.redis, "info", info_mock):
            assert _REAL_CHECK_REDIS_MASTER(correlator) is True
            assert _REAL_CHECK_REDIS_MASTER(correlator) is True  # second call within interval: cached
        assert info_mock.call_count == 1


class TestAddAlertValidation:
    def test_invalid_source_ip_returns_none(self):
        correlator = _make_correlator()
        result = correlator.add_alert({"source_ip": "not-an-ip", "alert_id": "A1"})
        assert result is None

    def test_oversized_resolved_ip_is_rejected(self):
        correlator = _make_correlator()
        fake_addr = MagicMock()
        fake_addr.__str__ = MagicMock(return_value="0" * 46)
        with patch("inference.correlation.ipaddress.ip_address", return_value=fake_addr):
            result = correlator.add_alert({"source_ip": "1.2.3.4", "alert_id": "A1"})
        assert result is None

    def test_threat_class_that_sanitizes_to_empty_falls_back_to_unknown_dedup_key(self):
        # safe_threat (sanitized) names the Redis dedup key -- it's a
        # separate thing from the raw threat_class string returned in the
        # incident's threat_classes list, which is never sanitized. A
        # threat_class that regex-sanitizes to "" must fall back to
        # "unknown" for the key rather than produce a malformed/empty key.
        correlator = _make_correlator()
        src_ip = "203.0.113.10"
        alert = {"source_ip": src_ip, "alert_id": "A1", "threat_class": "!!!@@@###"}
        correlator.add_alert(alert)  # must not raise building the dedup key
        assert correlator.redis.exists(f"{{{src_ip}}}:dedup:unknown")

    def test_unrecognized_severity_does_not_crash_the_lua_escalation_logic(self):
        # raw_sev falling back to "low" (rather than KeyError-ing on
        # sev_weights[raw_sev]) is what lets an alert with a garbage
        # severity string reach the Lua script at all.
        correlator = _make_correlator()
        alert = {"source_ip": "203.0.113.20", "alert_id": "A1", "threat_class": "X", "severity": "bogus-severity"}
        correlator.add_alert(alert)  # must not raise KeyError
        result = correlator.add_alert({**alert, "alert_id": "A2"})
        assert result is not None

    def test_race_conflict_marker_increments_the_race_counter(self):
        from inference.correlation import race_counter

        correlator = _make_correlator()
        before = race_counter._value.get()
        with patch.object(correlator, "_lua", return_value=[3, 2, []]):
            result = correlator.add_alert({"source_ip": "203.0.113.30", "alert_id": "A1"})
        assert result is None  # incident_flag == 2 is not == 1, so no incident is returned
        assert race_counter._value.get() == before + 1

    def test_redis_error_during_lua_execution_propagates(self):
        correlator = _make_correlator()
        with patch.object(correlator, "_lua", side_effect=redis_module.ConnectionError("down")):
            with pytest.raises(redis_module.ConnectionError):
                correlator.add_alert({"source_ip": "203.0.113.40", "alert_id": "A1"})


class TestIncidentAggregationFromHistory:
    def test_incident_aggregates_threat_classes_and_entities_across_prior_alerts(self):
        # Exercises the raw_alerts-snapshot loop directly: the SECOND
        # alert's own threat_class/alert_id alone would satisfy a weaker
        # assertion (they're also applied as a fallback when history is
        # empty) -- asserting on the FIRST alert's data too proves the
        # Lua script's lrange snapshot was actually parsed and aggregated,
        # not just the fallback path.
        correlator = _make_correlator()
        src_ip = "203.0.113.60"
        alert1 = {
            "alert_id": "HIST-1", "source_ip": src_ip, "destination_ip": "10.1.1.1",
            "threat_class": "Reconnaissance", "severity": "low", "mitre_tactic": "Discovery",
        }
        alert2 = {
            "alert_id": "HIST-2", "source_ip": src_ip, "destination_ip": "10.1.1.2",
            "threat_class": "C2 Beaconing", "severity": "high", "mitre_tactic": "Command and Control",
        }
        assert correlator.add_alert(alert1) is None  # first alert alone never triggers an incident
        incident = correlator.add_alert(alert2)

        assert incident is not None
        assert set(incident["threat_classes"]) == {"Reconnaissance", "C2 Beaconing"}
        assert set(incident["related_alert_ids"]) == {"HIST-1", "HIST-2"}
        assert set(incident["affected_entities"]) >= {src_ip, "10.1.1.1", "10.1.1.2"}
        assert set(incident["tactics"]) == {"Discovery", "Command and Control"}

    def test_malformed_history_entry_is_skipped_not_fatal(self):
        # One garbage entry in the Lua's alerts_snapshot (e.g. a lingering
        # non-JSON value from a schema change) must not crash the whole
        # aggregation -- it's logged and skipped, and the current alert's
        # own fallback data still produces a valid incident.
        correlator = _make_correlator()
        alert = {"alert_id": "A1", "source_ip": "203.0.113.70", "threat_class": "DDoS", "severity": "high"}
        with patch.object(correlator, "_lua", return_value=[2, 1, ["not valid json", "{}"]]):
            incident = correlator.add_alert(alert)
        assert incident is not None
        assert incident["threat_classes"] == ["DDoS"]  # fallback: history yielded nothing usable
        assert incident["related_alert_ids"] == ["A1"]

    def test_empty_history_snapshot_falls_back_to_the_current_alert(self):
        correlator = _make_correlator()
        alert = {"alert_id": "A1", "source_ip": "203.0.113.80", "threat_class": "Reconnaissance", "severity": "medium"}
        with patch.object(correlator, "_lua", return_value=[2, 1, []]):
            incident = correlator.add_alert(alert)
        assert incident is not None
        assert incident["threat_classes"] == ["Reconnaissance"]
        assert incident["related_alert_ids"] == ["A1"]


class TestRollbackAlertSeen:
    def test_invalid_source_ip_is_a_graceful_noop(self):
        correlator = _make_correlator()
        correlator.rollback_alert_seen({"source_ip": "not-an-ip", "alert_id": "A1"})  # must not raise

    def test_redis_error_during_rollback_is_logged_not_raised(self):
        correlator = _make_correlator()
        with patch.object(correlator, "_rollback_lua", side_effect=redis_module.ConnectionError("down")):
            correlator.rollback_alert_seen({"source_ip": "203.0.113.50", "alert_id": "A1"})  # must not raise
