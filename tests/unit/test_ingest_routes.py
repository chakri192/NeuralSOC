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

    def test_a_tenant_bs_sensor_cannot_hijack_tenant_as_existing_alert_via_an_alert_id_collision(self):
        """Regression test, now covering two layers of the same fix.

        api/models.py's alerts.alert_id originally carried a *global*
        UNIQUE constraint. Before bulk_upsert_alerts()/the per-item
        fallback scoped their "does this alert already exist" lookup to
        the caller's own tenant_id, tenant B's sensor sending an
        alert_id that already belonged to tenant A was treated as an
        UPDATE and silently reassigned that alert's tenant_id to B --
        overwriting tenant A's data and evicting the alert from tenant
        A's view entirely.

        The application-layer fix alone (with the old global constraint
        still in place) turned that into a *rejection*: tenant B's write
        would fail the underlying INSERT and get DLQ'd, since the table
        still couldn't hold two rows with the same alert_id at all. A
        follow-up migration (28d9095cde3b) replaced that global
        constraint with a composite (tenant_id, alert_id) one -- the
        correct end state, verified below: tenant B's alert_id="ALERT-1"
        is now neither a hijack nor a rejection, just its own
        completely independent row, coexisting with tenant A's.
        """
        tenant_a = _seed_tenant_and_admin(tenant_slug="acme", email="admin@acme.example.com")
        tenant_b = _seed_tenant_and_admin(tenant_slug="globex", email="admin@globex.example.com")
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            created_a = _create_sensor_token(client, token_a, tenant_a)
            r1 = client.post(
                "/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers={"Authorization": f"Bearer {created_a['token']}"}
            )
            assert r1.json() == {"accepted": 1, "failed": []}

            token_b = _login(client, "admin@globex.example.com")
            created_b = _create_sensor_token(client, token_b, tenant_b)
            colliding_alert = {**_SAMPLE_ALERT, "severity": "low", "threat_class": "Not A Hijack"}
            r2 = client.post(
                "/api/v1/ingest/alerts", json=[colliding_alert], headers={"Authorization": f"Bearer {created_b['token']}"}
            )

        # Tenant B's write succeeds -- it's a new row for tenant B, not a
        # collision, thanks to the composite constraint.
        assert r2.json() == {"accepted": 1, "failed": []}

        db = SessionLocal()
        rows = db.query(Alert).filter(Alert.alert_id == "ALERT-1").all()
        db.close()
        assert len(rows) == 2  # one row per tenant, same alert_id, no conflict
        by_tenant = {r.tenant_id: r for r in rows}
        assert by_tenant[tenant_a].severity == "critical"  # tenant A's original value, untouched
        assert by_tenant[tenant_a].threat_class == "DGA"
        assert by_tenant[tenant_b].severity == "low"  # tenant B's own, independent row
        assert by_tenant[tenant_b].threat_class == "Not A Hijack"

    def test_a_tenant_cannot_overwrite_its_own_alert_with_a_different_alert_ids_row(self):
        """The composite constraint narrows uniqueness to (tenant_id,
        alert_id) -- it must not also narrow it to nothing. The same
        tenant re-sending the same alert_id is still an upsert, not a
        new row every time."""
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id)
            headers = {"Authorization": f"Bearer {created['token']}"}
            client.post("/api/v1/ingest/alerts", json=[_SAMPLE_ALERT], headers=headers)
            client.post("/api/v1/ingest/alerts", json=[{**_SAMPLE_ALERT, "severity": "low"}], headers=headers)

        db = SessionLocal()
        rows = db.query(Alert).filter(Alert.alert_id == "ALERT-1", Alert.tenant_id == tenant_id).all()
        db.close()
        assert len(rows) == 1
        assert rows[0].severity == "low"

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


class TestListSensorTokens:
    def test_requires_users_manage_scope(self):
        tenant_id = _seed_tenant_and_admin()
        db = SessionLocal()
        db.add(User(tenant_id=tenant_id, email="analyst@acme.example.com", password_hash=_hasher.hash("pw"), role="analyst"))
        db.commit()
        db.close()
        with TestClient(app) as client:
            token = _login(client, "analyst@acme.example.com")
            r = client.get(f"/api/v1/ingest/tenants/{tenant_id}/sensor-tokens", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_lists_tokens_without_ever_exposing_the_cleartext_value(self):
        tenant_id = _seed_tenant_and_admin()
        with TestClient(app) as client:
            admin_token = _login(client, "admin@acme.example.com")
            created = _create_sensor_token(client, admin_token, tenant_id, name="Site sensor")
            r = client.get(
                f"/api/v1/ingest/tenants/{tenant_id}/sensor-tokens", headers={"Authorization": f"Bearer {admin_token}"}
            )
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["name"] == "Site sensor"
        assert rows[0]["is_active"] is True
        assert "token" not in rows[0]
        assert "token_hash" not in rows[0]
        assert created["token"] not in str(rows)

    def test_admin_cannot_list_a_different_tenants_sensor_tokens(self):
        tenant_a = _seed_tenant_and_admin(tenant_slug="acme", email="admin@acme.example.com")
        tenant_b = _seed_tenant_and_admin(tenant_slug="globex", email="admin@globex.example.com")
        with TestClient(app) as client:
            token_a = _login(client, "admin@acme.example.com")
            r = client.get(f"/api/v1/ingest/tenants/{tenant_b}/sensor-tokens", headers={"Authorization": f"Bearer {token_a}"})
        assert r.status_code == 403
