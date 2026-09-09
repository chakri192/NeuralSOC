"""api/audit.py's record_audit_event() and api/routes/audit.py's
GET /api/v1/audit -- Phase 6 ops hardening: who did what, when, per
tenant. Covers the writer (direct unit tests) and the reader (scope
gate, tenant isolation), plus integration checks that the routes this
session instrumented (login, triage, sensor-token creation) actually
call it.
"""
import fakeredis
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
from api.audit import record_audit_event
from api.database import Base, SessionLocal, engine
from api.main import app
from api.models import ADMIN, ANALYST, AuditLog, Tenant, User

_hasher = PasswordHasher()

Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def _isolated_redis(monkeypatch):
    fake = fakeredis.FakeStrictRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(deps, "get_redis_client", lambda: fake)


@pytest.fixture(autouse=True)
def _disable_rate_limiter():
    deps.limiter.enabled = False
    yield
    deps.limiter.enabled = True


@pytest.fixture(autouse=True)
def _clean_tables():
    db = SessionLocal()
    try:
        db.query(AuditLog).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()
    yield


def _seed_tenant_and_user(tenant_slug="acme", email="admin@acme.example.com", role=ADMIN):
    db = SessionLocal()
    try:
        tenant = Tenant(name=tenant_slug.title(), slug=tenant_slug)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        user = User(tenant_id=tenant.id, email=email, password_hash=_hasher.hash("pw"), role=role)
        db.add(user)
        db.commit()
        return tenant.id
    finally:
        db.close()


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": "pw"})
    assert r.status_code == 200, r.json()
    return r.json()["access_token"]


class TestRecordAuditEvent:
    def test_writes_a_row_with_every_field(self):
        tenant_id = _seed_tenant_and_user()
        db = SessionLocal()
        try:
            record_audit_event(
                db, "test.action", tenant_id=tenant_id, actor_user_id=1, actor_label="a@x.com",
                target="INC-1", detail="confirmed", ip_address="203.0.113.5",
            )
            row = db.query(AuditLog).filter(AuditLog.action == "test.action").first()
            assert row is not None
            assert row.tenant_id == tenant_id
            assert row.target == "INC-1"
            assert row.detail == "confirmed"
            assert row.ip_address == "203.0.113.5"
            assert row.created_at is not None
        finally:
            db.close()

    def test_never_raises_even_if_the_write_fails(self):
        db = SessionLocal()
        try:
            db.close()  # a closed session -- any operation on it raises
            record_audit_event(db, "test.action")  # must not raise
        finally:
            pass


class TestListAuditLog:
    def test_requires_users_manage_scope(self):
        tenant_id = _seed_tenant_and_user()
        db = SessionLocal()
        db.add(User(tenant_id=tenant_id, email="analyst@acme.example.com", password_hash=_hasher.hash("pw"), role=ANALYST))
        db.commit()
        db.close()
        with TestClient(app) as client:
            token = _login(client, "analyst@acme.example.com")
            r = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_only_shows_the_callers_own_tenant(self):
        tenant_a = _seed_tenant_and_user(tenant_slug="acme", email="admin@acme.example.com")
        tenant_b = _seed_tenant_and_user(tenant_slug="globex", email="admin@globex.example.com")
        db = SessionLocal()
        record_audit_event(db, "tenant_a.event", tenant_id=tenant_a, target="secret-a")
        record_audit_event(db, "tenant_b.event", tenant_id=tenant_b, target="secret-b")
        db.close()

        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token_a}"})

        assert r.status_code == 200
        actions = {row["action"] for row in r.json()}
        assert "tenant_a.event" in actions
        assert "tenant_b.event" not in actions

    def test_login_success_and_failure_are_both_recorded(self):
        _seed_tenant_and_user()
        with TestClient(app) as client:
            client.post("/api/v1/auth/login", json={"email": "admin@acme.example.com", "password": "wrong"})
            token = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})

        actions = [row["action"] for row in r.json()]
        assert "login.failure" in actions
        assert "login.success" in actions


class TestAuditIntegration:
    """The routes this session instrumented actually call
    record_audit_event() -- not just that the function itself works."""

    def test_triage_set_status_is_recorded(self):
        _seed_tenant_and_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            headers = {"Authorization": f"Bearer {token}"}
            client.post("/api/v1/triage/INC-1", json={"status": "acknowledged", "note": ""}, headers=headers)
            r = client.get("/api/v1/audit", headers=headers)

        entries = [row for row in r.json() if row["action"] == "triage.set_status"]
        assert len(entries) == 1
        assert entries[0]["target"] == "INC-1"
        assert entries[0]["detail"] == "acknowledged"

    def test_sensor_token_creation_is_recorded(self):
        tenant_id = _seed_tenant_and_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            headers = {"Authorization": f"Bearer {token}"}
            client.post(f"/api/v1/ingest/tenants/{tenant_id}/sensor-tokens", json={"name": "Site sensor"}, headers=headers)
            r = client.get("/api/v1/audit", headers=headers)

        entries = [row for row in r.json() if row["action"] == "sensor_token.created"]
        assert len(entries) == 1
        assert entries[0]["target"] == "Site sensor"

    def test_user_invite_is_recorded(self):
        tenant_id = _seed_tenant_and_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            headers = {"Authorization": f"Bearer {token}"}
            client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/invite",
                json={"email": "new@acme.example.com", "role": "analyst"},
                headers=headers,
            )
            r = client.get("/api/v1/audit", headers=headers)

        entries = [row for row in r.json() if row["action"] == "user.invited"]
        assert len(entries) == 1
        assert entries[0]["target"] == "new@acme.example.com"
