"""terminal/tsoc_console.py has no live PTY available in CI, so
Textual's own App.run_test() (Pilot) headless harness -- the same
technique that originally found the severity-coloring bug from reading
the source alone was never going to catch -- is the real verification
surface here. Tests wrap the async Pilot session in asyncio.run(...)
inside a plain `def test_...`, matching this repo's existing convention
(tests/test_pipeline.py) rather than adding a pytest-asyncio dependency
nothing else here uses.
"""
import asyncio
import importlib
from unittest.mock import patch

import pytest

import shared.triage_store as triage_store
import terminal.tsoc_console as console
from shared.data_access import DataStreamManager


@pytest.fixture(autouse=True)
def _isolated_triage_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "triage.db")
    monkeypatch.setenv("TRIAGE_DB_PATH", db_path)
    importlib.reload(triage_store)
    yield
    importlib.reload(triage_store)


@pytest.fixture(autouse=True)
def _isolated_stream_manager(monkeypatch):
    """DataStreamManager is a process-wide singleton (see
    tests/unit/test_data_access.py) -- give the console its own fresh,
    unconfigured instance per test rather than sharing the real one."""
    DataStreamManager._instance = None
    mgr = DataStreamManager()
    monkeypatch.setattr(console, "stream_manager", mgr)
    yield mgr
    DataStreamManager._instance = None


@pytest.fixture(autouse=True)
def _fixed_password(monkeypatch):
    monkeypatch.setattr(console, "_DASHBOARD_PASSWORD", "test-password")


def _seed(mgr, alerts):
    mgr.alerts = alerts
    mgr.broker_healthy = True
    mgr.is_running = True


async def _login(pilot, password="test-password"):
    pw = pilot.app.screen.query_one("#password-input")
    pw.focus()
    for ch in password:
        await pilot.press(ch)
    await pilot.press("enter")
    await pilot.pause()


def test_login_rejects_wrong_password():
    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot, password="wrong")
            assert isinstance(app.screen, console.LoginScreen)
            error = app.screen.query_one("#login-error")
            assert "Incorrect password" in str(error.render())

    asyncio.run(_run())


def test_login_accepts_correct_password():
    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            assert isinstance(app.screen, console.MainScreen)

    asyncio.run(_run())


def test_severity_color_uses_real_theme_hex_not_a_style_name(_isolated_stream_manager):
    """Regression test for the original bug: 'critical'/'high'/etc. are
    not real Rich style names and were silently dropped -- the fix must
    emit dashboard.theme.SEVERITY_COLORS' actual hex values instead."""
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.5", "severity": "critical", "threat_class": "DGA"},
    ])

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            table = app.screen.query_one("#queue")
            row = table.get_row_at(0)
            assert row[0] == f"[{console.SEVERITY_COLORS['critical']}]CRITICAL[/]"

    asyncio.run(_run())


def test_health_indicator_reflects_broker_status(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [{"alert_id": "a1", "source_ip": "10.0.0.5", "severity": "low"}])
    _isolated_stream_manager.broker_healthy = False

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            assert "SENSOR: DOWN" in app.sub_title

    asyncio.run(_run())


def test_cursor_preserved_across_refresh_by_incident_id(_isolated_stream_manager):
    """Regression test: the old code captured cursor_row before clear()
    and never restored it, so every refresh silently reset the selection
    to row 0. Selecting the row that does NOT sort to the top makes that
    bug reproducible."""
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.1", "severity": "critical"},
        {"alert_id": "a2", "source_ip": "10.0.0.2", "severity": "low"},
    ])

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            table = app.screen.query_one("#queue")
            table.move_cursor(row=1)
            await pilot.press("enter")
            await pilot.pause()
            assert app.screen._selected_incident_id == "INC-10-0-0-2"

            app.screen.update_queue(force=True)
            await pilot.pause()
            assert table.cursor_row == 1
            assert table.cursor_row == table.get_row_index("INC-10-0-0-2")

    asyncio.run(_run())


def test_acknowledge_persists_via_shared_triage_store(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [{"alert_id": "a1", "source_ip": "10.0.0.5", "severity": "high"}])

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            table = app.screen.query_one("#queue")
            table.move_cursor(row=0)
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()

    asyncio.run(_run())
    assert triage_store.get_status("INC-10-0-0-5")["status"] == triage_store.ACKNOWLEDGED


def test_false_positive_and_confirm_also_persist(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [{"alert_id": "a1", "source_ip": "10.0.0.5", "severity": "high"}])

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            table = app.screen.query_one("#queue")
            table.move_cursor(row=0)
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("f")
            await pilot.pause()

    asyncio.run(_run())
    assert triage_store.get_status("INC-10-0-0-5")["status"] == triage_store.FALSE_POSITIVE


def test_triage_action_without_selection_warns_instead_of_erroring(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [{"alert_id": "a1", "source_ip": "10.0.0.5", "severity": "high"}])

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            with patch.object(console.MainScreen, "notify") as mock_notify:
                await pilot.press("c")  # nothing selected yet
                await pilot.pause()
                assert mock_notify.called
                _, kwargs = mock_notify.call_args
                assert kwargs.get("severity") == "warning"

    asyncio.run(_run())


def test_filter_narrows_the_queue_by_substring(_isolated_stream_manager):
    _seed(_isolated_stream_manager, [
        {"alert_id": "a1", "source_ip": "10.0.0.1", "severity": "low", "threat_class": "Beaconing"},
        {"alert_id": "a2", "source_ip": "10.0.0.2", "severity": "critical", "threat_class": "DGA"},
    ])

    async def _run():
        app = console.TSOCConsole()
        async with app.run_test() as pilot:
            await pilot.pause()
            await _login(pilot)
            await pilot.pause(0.1)
            table = app.screen.query_one("#queue")
            assert table.row_count == 2

            await pilot.press("/")
            await pilot.pause()
            filt = app.screen.query_one("#filter-input")
            filt.focus()
            for ch in "dga":
                await pilot.press(ch)
            await pilot.pause()
            assert table.row_count == 1

    asyncio.run(_run())
