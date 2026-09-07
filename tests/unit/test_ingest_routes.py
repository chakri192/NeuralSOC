"""api/routes/ingest.py: the tenant-scoped ingestion boundary. A sensor
token identifies a *collector*, not a person -- authenticated by hashed
lookup against SensorToken, not the employee JWT/API-key path in
api/deps.py. The core property under test: a sensor token can only ever
write data tagged with its own tenant_id, and a caller can only mint a
sensor token for a tenant they themselves administer.
"""
import fakeredis
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
from api.database import Base, SessionLocal, engine
from api.main import app
from api.models import ADMIN, Alert, SensorToken, Tenant, User

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
        db.query(Alert).delete()
        db.query(SensorToken).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()
    yield


def _seed_tenant_and_admin(tenant_slug="acme", email="admin@acme.example.com"):
    db = SessionLocal()
    try:
        tenant = Tenant(name="Acme", slug=tenant_slug)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        admin = User(tenant_id=tenant.id, email=email, password_hash=_hasher.hash("pw"), role=ADMIN)
        db.add(admin)
        db.commit()
        return tenant.id
    finally:
        db.close()


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": "pw"})
    assert r.status_code == 200, r.json()
    return r.json()["access_token"]


def _create_sensor_token(client, admin_token, tenant_id, name="Site sensor"):
    r = client.post(
        f"/api/v1/ingest/tenants/{tenant_id}/sensor-tokens",
        json={"name": name},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201, r.json()
    return r.json()


_SAMPLE_ALERT = {
    "alert_id": "ALERT-1",
    "event_type": "conn",
    "timestamp": "2026-09-07T00:00:00Z",
    "threat_class": "DGA",
    "severity": "critical",
    "confidence_score": 0.9,
    "source_ip": "10.0.0.5",
}


class TestSensorTokenCreation:
    def test_requires_users_manage_scope(self):
        db_tenant_id = _seed_tenant_and_admin()
        db = SessionLocal()
        analyst = User(tenant_id=db_tenant_id, email="analyst@acme.example.com", password_hash=_hasher.hash("pw"), role="analyst")
        db.add(analyst)
        db.commit()
        db.close()
        with TestClient(app) as client:
            token = _login(client, "analyst@acme.example.com")
            r = client.post(
                f"/api/v1/ingest/tenants/{db_tenant_id}/sensor-tokens",
                json={"name": "x"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 403

    def test_admin_cannot_create_a_token_for_a_different_tenant(self):
        tenant_a = _seed_tenant_and_admin(tenant_slug="acme", email="admin@acme.example.com")
        tenant_b = _seed_tenant_and_admin(tenant_slug="globex", email="admin@globex.example.com")
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.post(
                f"/api/v1/ingest/tenants/{tenant_b}/sensor-tokens",
                json={"name": "x"},
                headers={"Authorization": f"Bearer {token_a}"},
            )
        assert r.status_code == 403
        assert tenant_a != tenant_b

    def test_returns_a_usable_cleartext_token_once(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            assert "token" in created and len(created["token"]) > 20

            db = SessionLocal()
            stored = db.query(SensorToken).filter(SensorToken.id == created["id"]).first()
            db.close()
            # The cleartext token is never persisted -- only its hash.
            assert stored.token_hash != created["token"]


class TestIngestAlerts:
    def test_rejects_missing_sensor_token(self):
        with TestClient(app) as client:
            r = client.post("/api/v1/ingest/alerts", json=[_SAMPLE_ALERT])
        assert r.status_code == 401

    def test_rejects_an_invalid_sensor_token(self):
        with TestClient(app) as client:
            r = client.post(
                "/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers={"Authorization": "Bearer not-a-real-token"}
            )
        assert r.status_code == 401

    def test_rejects_an_inactive_sensor_token(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)

        db = SessionLocal()
        sensor = db.query(SensorToken).filter(SensorToken.id == created["id"]).first()
        sensor.is_active = False
        db.commit()
        db.close()

        with TestClient(app) as client:
            r = client.post(
                "/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers={"Authorization": f"Bearer {created['token']}"}
            )
        assert r.status_code == 401

    def test_ingested_alert_is_stamped_with_the_sensors_tenant(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            r = client.post(
                "/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers={"Authorization": f"Bearer {created['token']}"}
            )
        assert r.status_code == 202
        assert r.json() == {"accepted": 1, "failed": []}

        db = SessionLocal()
        stored = db.query(Alert).filter(Alert.alert_id == "ALERT-1").first()
        db.close()
        assert stored.tenant_id == tenant_id

    def test_a_tenant_bs_sensor_token_can_never_tag_data_as_tenant_a(self):
        tenant_a = _seed_tenant_and_admin(tenant_slug="acme", email="admin@acme.example.com")
        tenant_b = _seed_tenant_and_admin(tenant_slug="globex", email="admin@globex.example.com")
        with TestClient(app) as client:
            token_b = _login(client, "admin@globex.example.com")
            created_b = _create_sensor_token(client, token_b, tenant_b)
            client.post(
                "/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers={"Authorization": f"Bearer {created_b['token']}"}
            )

        db = SessionLocal()
        stored = db.query(Alert).filter(Alert.alert_id == "ALERT-1").first()
        db.close()
        assert stored.tenant_id == tenant_b
        assert stored.tenant_id != tenant_a

    def test_ingest_upserts_an_existing_alert_by_alert_id(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            headers = {"Authorization": f"Bearer {created['token']}"}
            client.post("/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers=headers)
            updated = {**_SAMPLE_ALERT, "severity": "low"}
            r = client.post("/api/v1/ingest/alerts", json=[updated], headers=headers)
        assert r.status_code == 202

        db = SessionLocal()
        rows = db.query(Alert).filter(Alert.alert_id == "ALERT-1").all()
        db.close()
        assert len(rows) == 1  # updated in place, not duplicated
        assert rows[0].severity == "low"

    def test_empty_batch_is_a_no_op(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            r = client.post("/api/v1/ingest/alerts", json=[], headers={"Authorization": f"Bearer {created['token']}"})
        assert r.status_code == 202
        assert r.json() == {"accepted": 0, "failed": []}

    def test_rejects_a_payload_missing_required_fields(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            r = client.post(
                "/api/v1/ingest/alerts",
                json=[{"alert_id": "ALERT-BAD"}],  # missing event_type/timestamp/etc.
                headers={"Authorization": f"Bearer {created['token']}"},
            )
        assert r.status_code == 422

    def test_using_the_token_updates_last_used_at(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            client.post(
                "/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers={"Authorization": f"Bearer {created['token']}"}
            )
        db = SessionLocal()
        sensor = db.query(SensorToken).filter(SensorToken.id == created["id"]).first()
        db.close()
        assert sensor.last_used_at is not None
