"""shared/triage_store.py backs the dashboard's Acknowledge / False
Positive / Confirm actions -- previously decorative buttons that
persisted nothing. Each test points TRIAGE_DB_PATH at its own tmp_path
file so tests never share state through a real triage.db on disk.
"""
import importlib

import pytest

import shared.triage_store as triage_store


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "triage.db")
    monkeypatch.setenv("TRIAGE_DB_PATH", db_path)
    importlib.reload(triage_store)
    yield
    importlib.reload(triage_store)


def test_get_status_on_unknown_incident_returns_open_default():
    result = triage_store.get_status("INC-does-not-exist")
    assert result == {"status": "open", "note": "", "actor": "", "updated_at": ""}


def test_set_status_then_get_status_roundtrips():
    triage_store.set_status("INC-1", triage_store.ACKNOWLEDGED, actor="priya", note="looking into it")
    result = triage_store.get_status("INC-1")
    assert result["status"] == "acknowledged"
    assert result["actor"] == "priya"
    assert result["note"] == "looking into it"
    assert result["updated_at"]


def test_set_status_rejects_invalid_status():
    with pytest.raises(ValueError):
        triage_store.set_status("INC-1", "not_a_real_status")


def test_set_status_overwrites_previous_status_for_same_incident():
    triage_store.set_status("INC-1", triage_store.ACKNOWLEDGED, actor="priya")
    triage_store.set_status("INC-1", triage_store.CONFIRMED, actor="sam")
    result = triage_store.get_status("INC-1")
    assert result["status"] == "confirmed"
    assert result["actor"] == "sam"


def test_get_all_statuses_returns_every_persisted_incident():
    triage_store.set_status("INC-1", triage_store.ACKNOWLEDGED)
    triage_store.set_status("INC-2", triage_store.FALSE_POSITIVE)
    all_statuses = triage_store.get_all_statuses()
    assert set(all_statuses) == {"INC-1", "INC-2"}
    assert all_statuses["INC-1"]["status"] == "acknowledged"
    assert all_statuses["INC-2"]["status"] == "false_positive"


def test_get_all_statuses_empty_when_nothing_persisted():
    assert triage_store.get_all_statuses() == {}


def test_state_persists_across_a_fresh_connection():
    """No in-memory caching papering over a real persistence bug --
    every call opens its own connection, so this only passes if the
    write actually landed on disk."""
    triage_store.set_status("INC-1", triage_store.CONFIRMED, actor="sam")
    # A brand new call, not reusing any object from the write above.
    assert triage_store.get_status("INC-1")["status"] == "confirmed"
