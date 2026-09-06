"""shared/auth.py is the single source of truth for the default
dashboard/console credential -- both dashboard/app.py and
terminal/tsoc_console.py resolve through it, rather than each keeping
its own copy of the same fallback logic that could silently drift.
"""
from shared.auth import (
    DEFAULT_DASHBOARD_PASSWORD,
    DEFAULT_DASHBOARD_USERNAME,
    resolve_dashboard_password,
)


def test_falls_back_to_default_when_unset(monkeypatch):
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    assert resolve_dashboard_password(warn=False) == DEFAULT_DASHBOARD_PASSWORD


def test_uses_configured_password_when_set(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "correct-horse-battery-staple")
    assert resolve_dashboard_password(warn=False) == "correct-horse-battery-staple"


def test_warns_when_falling_back_and_warn_true(monkeypatch, capsys):
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    resolve_dashboard_password(warn=True)
    out = capsys.readouterr().out
    assert DEFAULT_DASHBOARD_USERNAME in out
    assert DEFAULT_DASHBOARD_PASSWORD in out


def test_no_warning_when_a_real_password_is_configured(monkeypatch, capsys):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "something-else")
    resolve_dashboard_password(warn=True)
    assert capsys.readouterr().out == ""


def test_no_warning_when_warn_is_false(monkeypatch, capsys):
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    resolve_dashboard_password(warn=False)
    assert capsys.readouterr().out == ""
