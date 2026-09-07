"""api/models.py: the tenants/users foundation for the multi-tenant
pivot. Alert.tenant_id is deliberately nullable for now (api/kafka_sink.py,
the only writer, doesn't supply one yet -- see the model's own comment),
while User.tenant_id is not, since every user is created by this codebase
itself and always belongs to exactly one tenant from the start.
"""
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from api.database import Base, SessionLocal, engine
from api.models import ADMIN, ANALYST, LEAD, ROLE_SCOPES, VALID_ROLES, Alert, Tenant, User

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def _clean_tables():
    db = SessionLocal()
    try:
        db.query(Alert).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()
    yield


def _make_tenant(db, slug="acme"):
    tenant = Tenant(name="Acme Corp", slug=slug)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def test_tenant_roundtrips():
    db = SessionLocal()
    try:
        tenant = _make_tenant(db)
        assert tenant.id is not None
        assert tenant.is_active is True
        assert tenant.created_at is not None
    finally:
        db.close()


def test_user_requires_a_tenant():
    """A User with no tenant_id must be rejected -- unlike Alert, there's
    no legacy writer that predates the tenant concept for users."""
    db = SessionLocal()
    try:
        db.add(User(email="a@example.com", password_hash="x", role=ANALYST))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_user_belongs_to_its_tenant():
    db = SessionLocal()
    try:
        tenant = _make_tenant(db)
        user = User(tenant_id=tenant.id, email="a@example.com", password_hash="x", role=ADMIN)
        db.add(user)
        db.commit()
        db.refresh(user)
        assert user.tenant.id == tenant.id
        assert user.role == ADMIN
        assert user.is_active is True
    finally:
        db.close()


def test_user_email_is_unique_across_tenants():
    """Email uniqueness is global, not per-tenant -- one person can't
    register the same address under two different tenants."""
    db = SessionLocal()
    try:
        tenant_a = _make_tenant(db, slug="acme")
        tenant_b = _make_tenant(db, slug="globex")
        db.add(User(tenant_id=tenant_a.id, email="dupe@example.com", password_hash="x", role=ANALYST))
        db.commit()
        db.add(User(tenant_id=tenant_b.id, email="dupe@example.com", password_hash="y", role=ANALYST))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_alert_tenant_id_is_nullable_for_now():
    """Regression guard for the deliberate compatibility gap: an alert
    inserted with no tenant_id (api/kafka_sink.py's current behavior)
    must not be rejected by the schema -- that lands in a later phase
    once every writer supplies one."""
    db = SessionLocal()
    try:
        alert = Alert(
            alert_id="ALERT-no-tenant",
            timestamp="2026-09-07T00:00:00Z",
            event_type="conn",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        assert alert.tenant_id is None
    finally:
        db.close()


def test_alert_can_be_scoped_to_a_tenant():
    db = SessionLocal()
    try:
        tenant = _make_tenant(db)
        alert = Alert(
            tenant_id=tenant.id,
            alert_id="ALERT-scoped",
            timestamp="2026-09-07T00:00:00Z",
            event_type="conn",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        assert alert.tenant.slug == "acme"
    finally:
        db.close()


def test_valid_roles_and_scope_mapping_are_consistent():
    assert VALID_ROLES == {ANALYST, LEAD, ADMIN}
    assert set(ROLE_SCOPES) == VALID_ROLES
    # Only admin manages other users -- everyone else is read + triage-write.
    assert "users:manage" in ROLE_SCOPES[ADMIN]
    assert "users:manage" not in ROLE_SCOPES[ANALYST]
    assert "users:manage" not in ROLE_SCOPES[LEAD]
    for role, scopes in ROLE_SCOPES.items():
        assert "alerts:read" in scopes, role
        assert "triage:write" in scopes, role


def _run_alembic(*args):
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=_PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_migration_applies_cleanly_to_a_fresh_database(tmp_path, monkeypatch):
    db_path = tmp_path / "fresh.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    result = _run_alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr

    import sqlite3

    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"tenants", "users", "alerts"} <= tables
    default_tenant = conn.execute("SELECT slug FROM tenants").fetchall()
    assert default_tenant == [("default",)]
    conn.close()


def test_migration_backfills_alerts_that_predate_the_tenant_column(tmp_path, monkeypatch):
    """The realistic scenario: a database already running the baseline
    schema, with real alert rows in it, upgrading straight through the
    tenant/user migration -- those rows must land on the bootstrap
    tenant, not be left orphaned with a NULL tenant_id."""
    db_path = tmp_path / "existing.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    baseline_only = _run_alembic("upgrade", "95bddea6b154")
    assert baseline_only.returncode == 0, baseline_only.stderr

    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO alerts (alert_id, timestamp, event_type) VALUES (?, ?, ?)",
        ("ALERT-pre-migration", "2026-09-07T00:00:00Z", "conn"),
    )
    conn.commit()
    conn.close()

    upgrade_rest = _run_alembic("upgrade", "head")
    assert upgrade_rest.returncode == 0, upgrade_rest.stderr

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT tenant_id FROM alerts WHERE alert_id = 'ALERT-pre-migration'"
    ).fetchone()
    default_tenant_id = conn.execute("SELECT id FROM tenants WHERE slug = 'default'").fetchone()[0]
    conn.close()
    assert row == (default_tenant_id,)


def test_migration_round_trips_downgrade_to_base(tmp_path, monkeypatch):
    db_path = tmp_path / "roundtrip.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    assert _run_alembic("upgrade", "head").returncode == 0
    result = _run_alembic("downgrade", "base")
    assert result.returncode == 0, result.stderr

    import sqlite3

    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert tables == {"alembic_version"}
