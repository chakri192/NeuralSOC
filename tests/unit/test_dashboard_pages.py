"""dashboard/pages/*.py had zero automated test coverage before this file
existed -- both TSOC-2026-02 stored-XSS sites (command_center.py,
investigate.py) lived in exactly this untested code. Streamlit's own
AppTest harness (streamlit.testing.v1) can execute a page script
in-process with a real (if headless) Streamlit runtime, which is what
makes mocking dashboard.session_data.fetch_alerts/fetch_stats and
shared.triage_store's functions at the module level actually take
effect -- the same pattern tests/unit/test_session_data.py already
established for session_data.py itself.

Known gap: st.dataframe(on_select="rerun") row selection (used by
command_center.py's incident queue to open its detail panel) has no
driver in AppTest as of this Streamlit version -- there is no
`.select_row()` or equivalent on AppTest's Dataframe element. That
specific code path (where TSOC-2026-02's command_center.py fix lives)
stays covered by the live browser verification recorded in this
project's audit report rather than an automated test here.
investigate.py's equivalent fields are reachable through its search box
and st.expander loop instead, with no dataframe involved, and are
covered below.
"""
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

import dashboard.session_data as session_data

_TOKEN = "test-token"

_MALICIOUS_ALERT = {
    "alert_id": "a1",
    "source_ip": '<img src=x onerror=alert(1)>',
    "destination_ip": '<script>alert(2)</script>',
    "severity": "critical",
    "threat_class": '<b>INJECTED</b>',
    "confidence_score": 0.9,
    "timestamp": "2026-09-07T00:00:00Z",
    "flow_id": "FLOW-1",
    "evidence": {},
}

_STATS = {"total_alerts": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}


@pytest.fixture(autouse=True)
def _isolated_cache():
    """st.cache_data's cache is process-global -- the same cross-test
    pollution risk tests/unit/test_session_data.py's fixture guards
    against, just reached through a full AppTest run instead of calling
    session_data's functions directly."""
    session_data._cached_alerts.clear()
    session_data._cached_stats.clear()
    yield
    session_data._cached_alerts.clear()
    session_data._cached_stats.clear()


def _run_page(path: str, alerts=None, stats=None, statuses=None) -> AppTest:
    at = AppTest.from_file(path, default_timeout=15)
    at.session_state["access_token"] = _TOKEN
    with patch("dashboard.session_data.fetch_alerts", return_value=alerts if alerts is not None else []), \
         patch("dashboard.session_data.fetch_stats", return_value=stats or _STATS), \
         patch("shared.triage_store.get_all_statuses", return_value=statuses or {}):
        at.run()
    return at


def _all_markdown_text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


class TestCommandCenter:
    def test_renders_kpis_and_incident_queue_without_a_live_backend(self):
        at = _run_page(
            "dashboard/pages/command_center.py",
            alerts=[{**_MALICIOUS_ALERT, "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8", "threat_class": "DGA"}],
        )
        assert not at.exception
        assert "Operations Overview" in _all_markdown_text(at)

    def test_shows_broker_unavailable_state_when_the_api_is_unreachable(self):
        at = AppTest.from_file("dashboard/pages/command_center.py", default_timeout=15)
        at.session_state["access_token"] = _TOKEN
        with patch("dashboard.session_data.fetch_alerts", side_effect=ConnectionError("down")):
            at.run()
        assert not at.exception
        assert "unavailable" in _all_markdown_text(at).lower()

    def test_no_alerts_state_renders_without_crashing(self):
        at = _run_page("dashboard/pages/command_center.py", alerts=[])
        assert not at.exception


class TestInvestigate:
    def test_empty_search_term_shows_the_prompt_state(self):
        at = _run_page("dashboard/pages/investigate.py")
        assert not at.exception
        assert any("Enter an IP" in i.value for i in at.info)

    def test_searching_a_malicious_alert_escapes_ip_pair_in_evidence_details(self):
        at = _run_page("dashboard/pages/investigate.py", alerts=[_MALICIOUS_ALERT])
        at.text_input[0].set_value("a1")  # matches _MALICIOUS_ALERT's alert_id
        with patch("dashboard.session_data.fetch_alerts", return_value=[_MALICIOUS_ALERT]), \
             patch("dashboard.session_data.fetch_stats", return_value=_STATS):
            at.run()

        assert not at.exception
        text = _all_markdown_text(at)
        # The raw tags must never appear un-escaped -- exactly the
        # TSOC-2026-02 regression this file exists to catch.
        assert "<img" not in text
        assert "<script" not in text
        assert "&lt;img" in text
        assert "&lt;script" in text

    def test_searching_a_malicious_alert_escapes_threat_class_in_related_incidents(self):
        at = _run_page("dashboard/pages/investigate.py", alerts=[_MALICIOUS_ALERT])
        at.text_input[0].set_value("a1")
        with patch("dashboard.session_data.fetch_alerts", return_value=[_MALICIOUS_ALERT]), \
             patch("dashboard.session_data.fetch_stats", return_value=_STATS):
            at.run()

        assert not at.exception
        text = _all_markdown_text(at)
        assert "<b>INJECTED</b>" not in text
        assert "&lt;b&gt;INJECTED&lt;/b&gt;" in text

    def test_searching_a_malicious_alert_escapes_the_evidence_expander_label(self):
        at = _run_page("dashboard/pages/investigate.py", alerts=[_MALICIOUS_ALERT])
        at.text_input[0].set_value("a1")
        with patch("dashboard.session_data.fetch_alerts", return_value=[_MALICIOUS_ALERT]), \
             patch("dashboard.session_data.fetch_stats", return_value=_STATS):
            at.run()

        assert not at.exception
        labels = [e.label for e in at.expander]
        assert any("INJECTED" in label for label in labels)
        assert not any("<b>" in label for label in labels)

    def test_no_match_shows_the_no_evidence_state(self):
        at = _run_page("dashboard/pages/investigate.py", alerts=[_MALICIOUS_ALERT])
        at.text_input[0].set_value("no-such-entity")
        with patch("dashboard.session_data.fetch_alerts", return_value=[_MALICIOUS_ALERT]), \
             patch("dashboard.session_data.fetch_stats", return_value=_STATS):
            at.run()
        assert not at.exception
        assert any("No evidence found" in i.value for i in at.info)


class TestNetwork:
    def test_renders_top_talkers_without_a_live_backend(self):
        alerts = [
            {**_MALICIOUS_ALERT, "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8", "threat_class": "DGA"},
            {**_MALICIOUS_ALERT, "alert_id": "a2", "source_ip": "10.0.0.6", "destination_ip": "8.8.4.4", "threat_class": "Scan"},
        ]
        at = _run_page("dashboard/pages/network.py", alerts=alerts)
        assert not at.exception
        assert "Top Talkers" in _all_markdown_text(at)

    def test_shows_broker_unavailable_state_when_the_api_is_unreachable(self):
        at = AppTest.from_file("dashboard/pages/network.py", default_timeout=15)
        at.session_state["access_token"] = _TOKEN
        with patch("dashboard.session_data.fetch_alerts", side_effect=ConnectionError("down")):
            at.run()
        assert not at.exception
        assert "unavailable" in _all_markdown_text(at).lower()


class TestHealth:
    def test_renders_platform_health_without_a_live_backend(self):
        at = _run_page("dashboard/pages/health.py", alerts=[_MALICIOUS_ALERT])
        assert not at.exception
        assert "Platform Health" in _all_markdown_text(at)

    def test_shows_broker_unavailable_state_when_the_api_is_unreachable(self):
        at = AppTest.from_file("dashboard/pages/health.py", default_timeout=15)
        at.session_state["access_token"] = _TOKEN
        with patch("dashboard.session_data.fetch_alerts", side_effect=ConnectionError("down")):
            at.run()
        assert not at.exception
        assert "unavailable" in _all_markdown_text(at).lower()
