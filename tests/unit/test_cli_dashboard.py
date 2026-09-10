"""dashboard/cli_dashboard.py is a plain rich.live.Live loop (not
Textual), so unlike terminal/tsoc_console.py it needs no Pilot harness --
generate_layout() is a normal method returning a Rich renderable, printed
through a real Console(record=True) and inspected via export_text()/the
raw ANSI escape sequences for color assertions.
"""
import pytest
from rich.console import Console

import dashboard.cli_dashboard as cli_dashboard
from shared.data_access import DataStreamManager


@pytest.fixture(autouse=True)
def _isolated_stream_manager(monkeypatch):
    """Mirrors tests/unit/test_data_access.py and
    tests/unit/test_tsoc_console.py's pattern: give this module its own
    fresh, unconfigured DataStreamManager instance per test."""
    DataStreamManager._instance = None
    mgr = DataStreamManager()
    monkeypatch.setattr(cli_dashboard, "stream_manager", mgr)
    yield mgr
    DataStreamManager._instance = None


@pytest.fixture(autouse=True)
def _fixed_password(monkeypatch):
    monkeypatch.setattr(cli_dashboard, "resolve_dashboard_password", lambda warn=True: "test-password")


def _seed(mgr, alerts, healthy=True, stats=None):
    mgr.alerts = alerts
    mgr.broker_healthy = healthy
    mgr.is_running = True
    if stats is not None:
        mgr.stats = stats


def _render_text(dash):
    console = Console(record=True, force_terminal=True, width=140, color_system="truecolor")
    console.print(dash.generate_layout())
    # export_text() defaults to clear=True, which empties the recorded
    # buffer -- pass clear=False on both calls so the second isn't left
    # exporting nothing.
    return console.export_text(clear=False), console.export_text(styles=True, clear=False)


def test_severity_color_uses_real_theme_hex(_isolated_stream_manager):
    """Regression guard: severity must resolve to a real
    dashboard.theme.SEVERITY_COLORS hex value, not an unstyled default."""
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
         "severity": "critical", "threat_class": "DGA", "confidence_score": 0.9,
         "timestamp": "2026-09-07T00:00:00Z"},
    ])
    dash = cli_dashboard.CLIDashboard()
    _, styled = _render_text(dash)
    assert "38;2;229;72;77" in styled  # RGB for #e5484d == SEVERITY_COLORS["critical"]


def test_health_status_reflects_broker_healthy_false(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
         "severity": "low", "threat_class": "Beaconing", "confidence_score": 0.3,
         "timestamp": "2026-09-07T00:00:00Z"},
    ], healthy=False)
    dash = cli_dashboard.CLIDashboard()
    text, _ = _render_text(dash)
    assert "DISCONNECTED" in text
    assert "ONLINE" not in text


def test_health_status_reflects_broker_healthy_true(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
         "severity": "low", "threat_class": "Beaconing", "confidence_score": 0.3,
         "timestamp": "2026-09-07T00:00:00Z"},
    ], healthy=True)
    dash = cli_dashboard.CLIDashboard()
    text, _ = _render_text(dash)
    assert "ONLINE" in text
    assert "DISCONNECTED" not in text


def test_markup_injection_in_threat_class_renders_as_literal_text(_isolated_stream_manager):
    """Regression test for the verified injection gap: a crafted
    threat_class carrying Rich bracket markup must render as literal
    text, not be interpreted as real styling. sanitize_ansi() alone
    (raw ANSI escapes only) does not catch this -- rich.markup.escape()
    must also be applied."""
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
         "severity": "high", "threat_class": "[bold red on white]INJECTED[/bold red on white]",
         "confidence_score": 0.5, "timestamp": "2026-09-07T00:00:00Z"},
    ])
    dash = cli_dashboard.CLIDashboard()
    text, _ = _render_text(dash)
    # Rich's Table wraps a long cell across multiple visual lines within
    # its column width, and other columns' content interleaves between
    # the wrapped lines in a plain text export -- so check a prefix that
    # (confirmed against actual output) survives intact on one line
    # rather than the full string. If "[bold red on white]" had been
    # interpreted as real markup instead of literal text, it would never
    # appear at all (consumed as a style tag).
    assert "[bold red on white]INJECTED" in text


def test_markup_injection_in_ip_fields_renders_as_literal_text(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "[blink]10.0.0.5[/blink]", "destination_ip": "8.8.8.8",
         "severity": "high", "threat_class": "DGA",
         "confidence_score": 0.5, "timestamp": "2026-09-07T00:00:00Z"},
    ])
    dash = cli_dashboard.CLIDashboard()
    text, _ = _render_text(dash)
    # The Source IP column is narrow enough that Rich truncates the full
    # string with an ellipsis -- but if "[blink]" had been interpreted as
    # real markup instead of literal text, it would never appear at all
    # (consumed as a style tag, leaving just "10.0.0.5" with an actual
    # blink style applied). Its literal presence is the proof.
    assert "[blink]" in text


def test_kpi_counts_reflect_the_true_total_not_just_the_visible_window(_isolated_stream_manager):
    """The KPI tiles used to be recomputed from stream_manager.get_alerts()
    -- itself capped at 100 by the API's own server-side limit -- so
    "Total Attacks Detected" could never read above 100 no matter how many
    attacks had actually landed, and looked stuck/broken during a live
    demo the moment total volume passed that cap. Fixed to read the real,
    uncapped counts from stream_manager's own polled /stats snapshot
    instead -- seeding a tiny 2-alert window alongside a much larger
    stats total here proves the tiles track the latter, not the former."""
    _seed(
        _isolated_stream_manager,
        [
            {"alert_id": "a1", "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1",
             "severity": "critical", "threat_class": "DGA", "confidence_score": 0.9,
             "timestamp": "2026-09-07T00:00:00Z"},
            {"alert_id": "a2", "source_ip": "10.0.0.2", "destination_ip": "2.2.2.2",
             "severity": "high", "threat_class": "Beaconing", "confidence_score": 0.6,
             "timestamp": "2026-09-07T00:00:01Z"},
        ],
        stats={"total_alerts": 542, "critical": 51, "high": 300, "medium": 140, "low": 51},
    )
    dash = cli_dashboard.CLIDashboard()
    text, _ = _render_text(dash)
    assert "542" in text
    assert "Total Attacks Detected" in text
    assert "51" in text  # critical
    assert "300" in text  # high
    assert "140" in text  # medium


def test_feed_table_still_shows_the_visible_alert_window(_isolated_stream_manager):
    """The KPI tiles above read from the global /stats snapshot now, but
    the actual feed table is still, correctly, just whatever alerts
    stream_manager currently holds (itself capped at 100 by the API) --
    there's no "global feed" to page through, only the latest window."""
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1",
         "severity": "critical", "threat_class": "DGA", "confidence_score": 0.9,
         "timestamp": "2026-09-07T00:00:00Z"},
        {"alert_id": "a2", "source_ip": "10.0.0.2", "destination_ip": "2.2.2.2",
         "severity": "high", "threat_class": "Beaconing", "confidence_score": 0.6,
         "timestamp": "2026-09-07T00:00:01Z"},
    ])
    dash = cli_dashboard.CLIDashboard()
    text, _ = _render_text(dash)
    assert "10.0.0.1" in text and "10.0.0.2" in text
    assert "Threat Signatures (last 2)" in text


def test_login_rejects_wrong_password_and_retries(monkeypatch):
    attempts = iter(["wrong-1", "wrong-2", "test-password"])
    monkeypatch.setattr(cli_dashboard.Prompt, "ask", lambda *a, **kw: next(attempts))
    assert cli_dashboard._login() is True


def test_login_gives_up_after_three_wrong_attempts(monkeypatch):
    monkeypatch.setattr(cli_dashboard.Prompt, "ask", lambda *a, **kw: "always-wrong")
    assert cli_dashboard._login() is False


def test_login_accepts_correct_password_on_first_try(monkeypatch):
    monkeypatch.setattr(cli_dashboard.Prompt, "ask", lambda *a, **kw: "test-password")
    assert cli_dashboard._login() is True


def test_sanitize_ansi_strips_raw_escape_sequences():
    assert cli_dashboard.sanitize_ansi("\x1b[31mred\x1b[0m") == "red"


def test_sanitize_ansi_does_not_touch_plain_bracket_text():
    """sanitize_ansi handles a different vector (raw ESC bytes) than
    rich.markup.escape() (bracket-tag markup) -- confirms the two are
    complementary, not redundant."""
    assert cli_dashboard.sanitize_ansi("[bold]not an escape[/bold]") == "[bold]not an escape[/bold]"
