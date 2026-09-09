"""terminal/tsoc_console.py has no live PTY available in CI, so
Textual's own App.run_test() (Pilot) headless harness is the real
verification surface here (same technique that originally found the
severity-coloring bug from reading the source alone). Mocks the HTTP
boundary (terminal.tsoc_console.requests / fetch_alerts, and
shared.triage_store's functions) rather than a live API -- the server
side of each of those is already covered by tests/unit/test_ingest_routes.py,
tests/unit/test_triage_routes.py, and tests/unit/test_triage_store.py.
"""
import asyncio
from unittest.mock import MagicMock, patch

import requests

import terminal.tsoc_console as console

_SAMPLE_ALERTS = [
    {
        "alert_id": "a1",
        "source_ip": "10.0.0.5",
        "destination_ip": "8.8.8.8",
        "severity": "critical",
        "threat_class": "DGA",
        "confidence_score": 0.9,
        "timestamp": "2026-09-07T00:00:00Z",
    },
]


def _login_response(status_code=200, token="fake-jwt"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"access_token": token}
    return resp


async def _login(pilot, email="analyst@acme.example.com", password="pw"):
    screen = pilot.app.screen
    screen.query_one("#email-input").focus()
    for ch in email:
        await pilot.press(ch)
    await pilot.press("enter")  # moves focus to the password field
    for ch in password:
        await pilot.press(ch)
    await pilot.press("enter")  # submits
    await pilot.pause()


def test_login_rejects_wrong_password():
    async def _run():
        with patch("terminal.tsoc_console.requests.post", return_value=_login_response(status_code=401)):
            app = console.TSOCConsole()
            async with app.run_test() as pilot:
                await pilot.pause()
                await _login(pilot, password="wrong")
                assert isinstance(app.screen, console.LoginScreen)
                error = app.screen.query_one("#login-error")
                assert "Incorrect" in str(error.render())

    asyncio.run(_run())


def test_login_accepts_correct_credentials():
    async def _run():
        with patch("terminal.tsoc_console.requests.post", return_value=_login_response()):
            app = console.TSOCConsole()
            async with app.run_test() as pilot:
                await pilot.pause()
                with patch("terminal.tsoc_console.fetch_alerts", return_value=[]), \
                     patch("terminal.tsoc_console.triage_store.get_all_statuses", return_value={}):
                    await _login(pilot)
                    assert isinstance(app.screen, console.MainScreen)

    asyncio.run(_run())


def test_login_shows_a_clear_message_for_an_mfa_enabled_account_instead_of_crashing():
    """api/routes/auth.py's login() returns {mfa_required: true, mfa_token:
    ...} with no access_token once MFA is enabled -- this console has no
    code-entry screen to complete that challenge with yet (unlike
    dashboard/app.py). Regression guard for the KeyError that a bare
    resp.json()["access_token"] would have raised here."""
    mfa_resp = MagicMock()
    mfa_resp.status_code = 200
    mfa_resp.json.return_value = {"mfa_required": True, "mfa_token": "short-lived-token"}

    async def _run():
        with patch("terminal.tsoc_console.requests.post", return_value=mfa_resp):
            app = console.TSOCConsole()
            async with app.run_test() as pilot:
                await pilot.pause()
                await _login(pilot)
                assert isinstance(app.screen, console.LoginScreen)
                error = app.screen.query_one("#login-error")
                assert "MFA" in str(error.render())

    asyncio.run(_run())


async def _boot_to_main_screen(pilot, alerts=_SAMPLE_ALERTS, statuses=None):
    with patch("terminal.tsoc_console.requests.post", return_value=_login_response()):
        with patch("terminal.tsoc_console.fetch_alerts", return_value=alerts), \
             patch("terminal.tsoc_console.triage_store.get_all_statuses", return_value=statuses or {}):
            await _login(pilot)
            await pilot.pause(0.1)


def test_severity_color_uses_real_theme_hex_not_a_style_name():
    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot)
            table = app.screen.query_one("#queue")
            row = table.get_row_at(0)
            assert row[0] == f"[{console.SEVERITY_COLORS['critical']}]CRITICAL[/]"

    asyncio.run(_run())


def test_health_indicator_reflects_a_fetch_failure():
    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot)
            assert "SENSOR: HEALTHY" in app.sub_title

            with patch("terminal.tsoc_console.fetch_alerts", side_effect=requests.ConnectionError("down")):
                app.screen.update_queue(force=True)
            assert "SENSOR: DOWN" in app.sub_title

    asyncio.run(_run())


def test_cursor_preserved_across_refresh_by_incident_id():
    """Regression test: the old bug reset the cursor to row 0 on every
    refresh. Selecting the row that does NOT sort to the top (the
    low-severity one) makes that bug reproducible."""
    alerts = [
        {"alert_id": "a1", "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1", "severity": "critical",
         "threat_class": "DGA", "confidence_score": 0.9, "timestamp": "2026-09-07T00:00:00Z"},
        {"alert_id": "a2", "source_ip": "10.0.0.2", "destination_ip": "2.2.2.2", "severity": "low",
         "threat_class": "Beaconing", "confidence_score": 0.3, "timestamp": "2026-09-07T00:00:01Z"},
    ]

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot, alerts=alerts)
            table = app.screen.query_one("#queue")
            table.move_cursor(row=1)
            with patch("terminal.tsoc_console.fetch_alerts", return_value=alerts), \
                 patch("terminal.tsoc_console.triage_store.get_status", return_value={"status": "open"}):
                await pilot.press("enter")
                await pilot.pause()
            assert app.screen._selected_incident_id == "INC-10-0-0-2"

            with patch("terminal.tsoc_console.fetch_alerts", return_value=alerts), \
                 patch("terminal.tsoc_console.triage_store.get_all_statuses", return_value={}):
                app.screen.update_queue(force=True)
            assert table.cursor_row == 1
            assert table.cursor_row == table.get_row_index("INC-10-0-0-2")

    asyncio.run(_run())


def test_acknowledge_calls_triage_store_with_token_and_incident_id_not_a_free_text_actor():
    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot)
            table = app.screen.query_one("#queue")
            table.move_cursor(row=0)
            with patch("terminal.tsoc_console.fetch_alerts", return_value=_SAMPLE_ALERTS), \
                 patch("terminal.tsoc_console.triage_store.get_status", return_value={"status": "open"}):
                await pilot.press("enter")
                await pilot.pause()

            with patch("terminal.tsoc_console.triage_store.set_status") as mock_set_status, \
                 patch("terminal.tsoc_console.triage_store.get_all_statuses", return_value={}), \
                 patch("terminal.tsoc_console.fetch_alerts", return_value=_SAMPLE_ALERTS):
                await pilot.press("a")
                await pilot.pause()

            mock_set_status.assert_called_once_with("fake-jwt", "INC-10-0-0-5", console.triage_store.ACKNOWLEDGED)

    asyncio.run(_run())


def test_row_selection_deserializes_string_evidence_from_the_real_api_wire_format():
    """Regression test: api/schemas.py's AlertResponse sends `evidence` as
    a JSON string (matching api/models.py's underlying Text column), not
    a parsed object. Before shared/data_access.py's fetch_alerts() gained
    the same deserialization DataStreamManager.get_alerts() already had,
    this console's detail pane silently rendered "No raw metadata facts
    extracted" / "no ML models triggered" for every single incident,
    since shared.formatters.categorize_evidence() rejects a bare string
    and returns three empty dicts. Only the HTTP layer
    (shared.data_access.requests.get) is mocked here, not fetch_alerts
    itself, so the real deserialization actually runs.
    """
    alert_with_string_evidence = dict(_SAMPLE_ALERTS[0], evidence='{"bytes_out": 48213, "ml_score": 0.9}')

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = [alert_with_string_evidence]
    resp.raise_for_status.side_effect = None

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot, alerts=[alert_with_string_evidence])
            table = app.screen.query_one("#queue")
            table.move_cursor(row=0)
            with patch("shared.data_access.requests.get", return_value=resp), \
                 patch("terminal.tsoc_console.triage_store.get_status", return_value={"status": "open"}):
                await pilot.press("enter")
                await pilot.pause()

            detail_text = str(app.screen.query_one("#detail-pane").render())
            assert "Bytes Out: 48213" in detail_text
            assert "Ml Score: 0.9" in detail_text
            assert "No raw metadata facts extracted" not in detail_text
            assert "no ML models triggered" not in detail_text

    asyncio.run(_run())


def test_triage_action_without_selection_warns_instead_of_erroring():
    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot)
            with patch.object(console.MainScreen, "notify") as mock_notify:
                await pilot.press("c")  # nothing selected yet
                await pilot.pause()
                assert mock_notify.called
                _, kwargs = mock_notify.call_args
                assert kwargs.get("severity") == "warning"

    asyncio.run(_run())


def test_filter_narrows_the_queue_by_substring():
    alerts = [
        {"alert_id": "a1", "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1", "severity": "low",
         "threat_class": "Beaconing", "confidence_score": 0.3, "timestamp": "2026-09-07T00:00:00Z"},
        {"alert_id": "a2", "source_ip": "10.0.0.2", "destination_ip": "2.2.2.2", "severity": "critical",
         "threat_class": "DGA", "confidence_score": 0.9, "timestamp": "2026-09-07T00:00:01Z"},
    ]

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _boot_to_main_screen(pilot, alerts=alerts)
            table = app.screen.query_one("#queue")
            assert table.row_count == 2

            await pilot.press("/")
            await pilot.pause()
            filt = app.screen.query_one("#filter-input")
            filt.focus()
            with patch("terminal.tsoc_console.fetch_alerts", return_value=alerts), \
                 patch("terminal.tsoc_console.triage_store.get_all_statuses", return_value={}):
                for ch in "dga":
                    await pilot.press(ch)
                await pilot.pause()
            assert table.row_count == 1

    asyncio.run(_run())
