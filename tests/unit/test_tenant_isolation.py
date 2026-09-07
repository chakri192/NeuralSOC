"""Cross-tenant data isolation: the property the entire multi-tenant
pivot exists for. api/deps.py's scope_to_tenant() is the single chokepoint
every alert/stats query goes through -- these tests prove a Tenant A
JWT can never read Tenant B's alerts or aggregate stats via any route,
while the static service key (which predates tenants and holds every
scope) deliberately still sees everything.
"""
import os

import fakeredis
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
from api.database import Base, SessionLocal, engine
from api.main import app
from api.models import ADMIN, Alert, Tenant, User

_hasher = PasswordHasher()
_API_KEY = os.environ["TSOC_API_KEY"]

Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def _isolated_redis(monkeypatch):
    # See tests/unit/test_auth_routes.py's _isolated_redis for why an
    # explicit FakeServer is needed rather than the no-args default.
    fake = fakeredis.FakeStrictRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(deps, "get_redis_client", lambda: fake)


@pytest.fixture(autouse=True)
def _disable_rate_limiter():
    # These tests are about tenant isolation, not the login rate limit
    # (already covered by tests/test_api_endpoints.py and
    # tests/unit/test_auth_routes.py) -- avoid the same shared,
    # process-wide budget every other file's login calls also draw from.
    deps.limiter.enabled = False
    yield
    deps.limiter.enabled = True


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


def _seed_two_tenants():
    db = SessionLocal()
    try:
        tenant_a = Tenant(name="Acme", slug="acme")
        tenant_b = Tenant(name="Globex", slug="globex")
        db.add_all([tenant_a, tenant_b])
        db.commit()
        db.refresh(tenant_a)
        db.refresh(tenant_b)

        user_a = User(tenant_id=tenant_a.id, email="admin@acme.example.com", password_hash=_hasher.hash("pw"), role=ADMIN)
        user_b = User(tenant_id=tenant_b.id, email="admin@globex.example.com", password_hash=_hasher.hash("pw"), role=ADMIN)
        db.add_all([user_a, user_b])

        alert_a = Alert(tenant_id=tenant_a.id, alert_id="ALERT-A-1", timestamp="2026-09-07T00:00:00Z", event_type="conn", severity="critical")
        alert_b = Alert(tenant_id=tenant_b.id, alert_id="ALERT-B-1", timestamp="2026-09-07T00:00:00Z", event_type="conn", severity="high")
        db.add_all([alert_a, alert_b])
        db.commit()

        return tenant_a.id, tenant_b.id
    finally:
        db.close()


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": "pw"})
    assert r.status_code == 200, r.json()
    return r.json()["access_token"]


class TestAlertListIsolation:
    def test_tenant_a_never_sees_tenant_bs_alerts(self):
        _seed_two_tenants()
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token_a}"})
        assert r.status_code == 200
        alert_ids = {a["alert_id"] for a in r.json()}
        assert alert_ids == {"ALERT-A-1"}

    def test_tenant_b_never_sees_tenant_as_alerts(self):
        _seed_two_tenants()
        with TestClient(app) as client:
            token_b = _login(client, "admin@globex.example.com")
            r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token_b}"})
        assert r.status_code == 200
        alert_ids = {a["alert_id"] for a in r.json()}
        assert alert_ids == {"ALERT-B-1"}

    def test_static_service_key_still_sees_every_tenant(self):
        """The trusted-internal-caller credential predates tenants and
        holds every scope -- it must keep working exactly as before."""
        _seed_two_tenants()
        with TestClient(app) as client:
            r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {_API_KEY}"})
        assert r.status_code == 200
        alert_ids = {a["alert_id"] for a in r.json()}
        assert alert_ids == {"ALERT-A-1", "ALERT-B-1"}


class TestSingleAlertIsolation:
    def test_cannot_fetch_another_tenants_alert_by_id(self):
        _seed_two_tenants()
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/alerts/ALERT-B-1", headers={"Authorization": f"Bearer {token_a}"})
        # 404, not 403 -- same "don't confirm it exists" reasoning as
        # login's identical wrong-password/unknown-email response.
        assert r.status_code == 404

    def test_can_fetch_own_tenants_alert_by_id(self):
        _seed_two_tenants()
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/alerts/ALERT-A-1", headers={"Authorization": f"Bearer {token_a}"})
        assert r.status_code == 200
        assert r.json()["alert_id"] == "ALERT-A-1"


class TestStatsIsolation:
    def test_stats_reflect_only_the_callers_own_tenant(self):
        _seed_two_tenants()
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {token_a}"})
        assert r.status_code == 200
        body = r.json()
        assert body["total_alerts"] == 1
        assert body["critical"] == 1
        assert body["high"] == 0  # Tenant B's alert must not be counted

    def test_static_service_key_stats_include_every_tenant(self):
        _seed_two_tenants()
        with TestClient(app) as client:
            r = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {_API_KEY}"})
        assert r.status_code == 200
        body = r.json()
        assert body["total_alerts"] == 2
        assert body["critical"] == 1
        assert body["high"] == 1
