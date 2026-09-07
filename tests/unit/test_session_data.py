"""dashboard/session_data.py replaced shared/data_access.py's
DataStreamManager singleton on the four dashboard pages (command_center,
investigate, network, health) specifically to fix a real cross-tenant
data leak: DataStreamManager authenticates with one static, all-tenant
TSOC_API_KEY shared by every Streamlit session in the process, so every
logged-in employee saw every tenant's alerts/incidents/stats regardless
of which tenant they actually belonged to. These tests exist to prove
that gap is actually closed -- most importantly
test_different_tokens_never_see_each_others_cached_data below, which is
the direct regression test for the leak itself.

streamlit.session_state and st.cache_data both work outside a real
`streamlit run` process (confirmed empirically: they log a "bare mode"
warning but function correctly), which is what makes testing this module
directly possible without Streamlit's AppTest harness.
"""
from unittest.mock import patch

import pytest
import streamlit as st

from dashboard import session_data


@pytest.fixture(autouse=True)
def _isolated_session_and_cache():
    """st.cache_data's cache is process-global, not per-test -- without
    clearing it, one test's mocked return value for a given token would
    leak into the next test that happens to reuse that token (the same
    cross-test-pollution shape the fakeredis tests elsewhere in this repo
    hit, just via Streamlit's cache instead of a fake Redis server)."""
    st.session_state.clear()
    session_data._cached_alerts.clear()
    session_data._cached_stats.clear()
    yield
    st.session_state.clear()
    session_data._cached_alerts.clear()
    session_data._cached_stats.clear()


_ALERT_A = {"alert_id": "a1", "source_ip": "10.0.0.1", "severity": "critical", "evidence": {}}
_ALERT_B = {"alert_id": "b1", "source_ip": "10.0.0.2", "severity": "low", "evidence": {}}


def test_get_alerts_returns_the_fetched_alerts_for_the_current_sessions_token():
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_A]) as mock_fetch:
        result = session_data.get_alerts()

    mock_fetch.assert_called_once_with("tenant-a-token")
    assert result == [_ALERT_A]


def test_get_alerts_returns_an_empty_list_on_any_fetch_failure():
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", side_effect=ConnectionError("down")):
        assert session_data.get_alerts() == []


def test_different_tokens_never_see_each_others_cached_data():
    """The core regression test: two different sessions (two different
    tenants' employees) must never receive each other's alerts, even
    though both reads happen well within the cache's TTL window."""
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_A]):
        alerts_for_a = session_data.get_alerts()

    st.session_state["access_token"] = "tenant-b-token"
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_B]):
        alerts_for_b = session_data.get_alerts()

    assert alerts_for_a == [_ALERT_A]
    assert alerts_for_b == [_ALERT_B]
    assert alerts_for_b != alerts_for_a


def test_repeated_calls_within_the_ttl_hit_the_cache_not_the_network():
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_A]) as mock_fetch:
        session_data.get_alerts()
        session_data.get_alerts()
        session_data.get_alerts()

    mock_fetch.assert_called_once()


def test_get_incidents_synthesizes_from_get_alerts():
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_A, _ALERT_B]):
        incidents = session_data.get_incidents()

    assert {i["incident_id"] for i in incidents} == {"INC-10-0-0-1", "INC-10-0-0-2"}


def test_status_reports_healthy_with_alert_and_stat_counts():
    st.session_state["access_token"] = "tenant-a-token"
    stats = {"total_alerts": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_A]), \
         patch("dashboard.session_data.fetch_stats", return_value=stats):
        result = session_data.status()

    assert result["broker_healthy"] is True
    assert result["alert_count"] == 1
    assert result["incident_count"] == 1
    assert result["stats"] == stats
    assert result["last_event_time"] > 0


def test_status_reports_unhealthy_on_failure_with_no_prior_success():
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", side_effect=ConnectionError("down")):
        result = session_data.status()

    assert result["broker_healthy"] is False
    assert result["last_event_time"] == 0.0
    assert result["alert_count"] == 0


def test_status_keeps_the_last_good_timestamp_after_a_later_failure():
    st.session_state["access_token"] = "tenant-a-token"
    with patch("dashboard.session_data.fetch_alerts", return_value=[_ALERT_A]), \
         patch("dashboard.session_data.fetch_stats", return_value={}):
        healthy_result = session_data.status()

    session_data._cached_alerts.clear()  # force a real re-fetch, bypassing the TTL cache
    with patch("dashboard.session_data.fetch_alerts", side_effect=ConnectionError("down")):
        unhealthy_result = session_data.status()

    assert unhealthy_result["broker_healthy"] is False
    assert unhealthy_result["last_event_time"] == healthy_result["last_event_time"]
