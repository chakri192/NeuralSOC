"""api/routes/triage.py: incident triage as a real, tenant-scoped,
identity-verified Postgres table -- replacing shared/triage_store.py's
local SQLite file (never shared across processes/machines) and its
free-text "actor" (never cross-checked against who was authenticated).
"""
import os

import fakeredis
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
from api.database import Base, SessionLocal, engine
from api.main import app
from api.models import ADMIN, IncidentTriage, Tenant, User

_hasher = PasswordHasher()
_API_KEY = os.environ["TSOC_API_KEY"]

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
        db.query(IncidentTriage).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()
    yield


def _seed_tenant_and_user(tenant_slug, email):
    db = SessionLocal()
    try:
        tenant = Tenant(name=tenant_slug.title(), slug=tenant_slug)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        user = User(tenant_id=tenant.id, email=email, password_hash=_hasher.hash("pw"), role=ADMIN)
        db.add(user)
        db.commit()
        return tenant.id
    finally:
        db.close()


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": "pw"})
    assert r.status_code == 200, r.json()
    return r.json()["access_token"]


class TestReadDefaults:
    def test_unset_incident_returns_open_default(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/triage/INC-10-0-0-5", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json() == {"status": "open", "note": "", "actor": "", "updated_at": ""}

    def test_bulk_read_empty_when_nothing_set(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/triage", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json() == {}


class TestSetStatus:
    def test_sets_status_with_the_real_authenticated_actor(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            r = client.post(
                "/api/v1/triage/INC-10-0-0-5",
                json={"status": "acknowledged", "note": "looking into it"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "acknowledged"
        assert body["note"] == "looking into it"
        assert body["actor"] == "admin@acme.example.com"  # the JWT's own identity, not client-supplied
        assert body["updated_at"]

    def test_rejects_an_invalid_status(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            r = client.post(
                "/api/v1/triage/INC-1", json={"status": "not_a_real_status"}, headers={"Authorization": f"Bearer {token}"}
            )
        assert r.status_code == 422

    def test_updating_an_existing_incident_overwrites_in_place(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com")
            headers = {"Authorization": f"Bearer {token}"}
            client.post("/api/v1/triage/INC-1", json={"status": "acknowledged"}, headers=headers)
            r = client.post("/api/v1/triage/INC-1", json={"status": "confirmed"}, headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "confirmed"

        db = SessionLocal()
        rows = db.query(IncidentTriage).filter(IncidentTriage.incident_id == "INC-1").all()
        db.close()
        assert len(rows) == 1  # overwritten, not duplicated

    def test_static_service_key_cannot_set_status(self):
        """The service key holds every scope but represents no one --
        "who triaged this" is meaningless for it."""
        with TestClient(app) as client:
            r = client.post(
                "/api/v1/triage/INC-1", json={"status": "acknowledged"}, headers={"Authorization": f"Bearer {_API_KEY}"}
            )
        assert r.status_code == 400


class TestTenantIsolation:
    def test_tenant_a_cannot_see_tenant_bs_triage_state(self):
        tenant_a_id = _seed_tenant_and_user("acme", "admin@acme.example.com")
        tenant_b_id = _seed_tenant_and_user("globex", "admin@globex.example.com")
        assert tenant_a_id != tenant_b_id

        with TestClient(app) as client:
            token_b = _login(client, "admin@globex.example.com")
            client.post(
                "/api/v1/triage/INC-SHARED-IP", json={"status": "confirmed"}, headers={"Authorization": f"Bearer {token_b}"}
            )

            token_a = _login(client, "admin@acme.example.com")
            # Same incident_id string -- two different tenants' networks
            # can both see traffic from the same IP -- must not collide.
            r = client.get("/api/v1/triage/INC-SHARED-IP", headers={"Authorization": f"Bearer {token_a}"})
        assert r.json()["status"] == "open"  # Tenant A's own view: untouched

    def test_bulk_read_reflects_only_the_callers_own_tenant(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        _seed_tenant_and_user("globex", "admin@globex.example.com")

        with TestClient(app) as client:
            token_b = _login(client, "admin@globex.example.com")
            client.post(
                "/api/v1/triage/INC-B-1", json={"status": "confirmed"}, headers={"Authorization": f"Bearer {token_b}"}
            )

            token_a = _login(client, "admin@acme.example.com")
            client.post(
                "/api/v1/triage/INC-A-1", json={"status": "acknowledged"}, headers={"Authorization": f"Bearer {token_a}"}
            )
            r = client.get("/api/v1/triage", headers={"Authorization": f"Bearer {token_a}"})
        assert set(r.json().keys()) == {"INC-A-1"}

    def test_static_service_key_reads_reflect_every_tenant(self):
        _seed_tenant_and_user("acme", "admin@acme.example.com")
        _seed_tenant_and_user("globex", "admin@globex.example.com")
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            client.post(
                "/api/v1/triage/INC-A-1", json={"status": "acknowledged"}, headers={"Authorization": f"Bearer {token_a}"}
            )
            r = client.get("/api/v1/triage", headers={"Authorization": f"Bearer {_API_KEY}"})
        assert set(r.json().keys()) == {"INC-A-1"}
