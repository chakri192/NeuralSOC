"""Integration tests: Kafka-shaped ingestion -> the real tenant-scoped
ingest API -> real (sqlite) DB -> real authenticated FastAPI read
endpoint, exercised together end-to-end.

tests/test_api_endpoints.py covers the auth boundary in isolation
(always against an empty DB); tests/unit/test_kafka_sink.py covers
process_batch's validation-before-send logic in isolation (with
ingest_fn mocked); tests/unit/test_ingest_routes.py covers the ingest
endpoint's own tenant-isolation behavior in isolation. Neither
previously proved that a message accepted by the ingestion pipeline is
actually the same data a caller reads back through the read API, or
that a message REJECTED by the pipeline never becomes visible through
it -- this file closes that gap, now routing process_batch's ingest_fn
through the real ingest endpoint (via TestClient, in-process -- no real
network socket) instead of a direct database write.
"""
import os

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
from api.database import Base, SessionLocal, engine
from api.kafka_sink import process_batch
from api.main import app
from api.models import ADMIN, Alert, SensorToken, Tenant, User

API_KEY = os.environ["TSOC_API_KEY"]
AUTH_HEADERS = {"Authorization": f"Bearer {API_KEY}"}
_hasher = PasswordHasher()

# api/kafka_sink.py no longer bootstraps the schema as an import-time
# side effect (it doesn't hold a database connection at all anymore) --
# this file needs its own tables the same way tests/unit/test_models.py
# and friends already do, so it still works when run standalone.
Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def _disable_rate_limiter():
    # Each test logs in once via _provision_sensor_token -- avoid the
    # shared, process-wide login rate-limit budget other test files'
    # own login calls also draw from (see
    # tests/unit/test_auth_routes.py's identical fixture).
    deps.limiter.enabled = False
    yield
    deps.limiter.enabled = True


@pytest.fixture(autouse=True)
def _clean_tables():
    def _clear():
        db = SessionLocal()
        try:
            db.query(Alert).delete()
            db.query(SensorToken).delete()
            db.query(User).delete()
            db.query(Tenant).delete()
            db.commit()
        finally:
            db.close()

    _clear()
    yield
    _clear()


def _provision_sensor_token(client: TestClient) -> str:
    """A tenant, an admin, and a sensor token for it -- the real path a
    collector's credential comes from (POST .../sensor-tokens, admin-only),
    not a shortcut around it."""
    db = SessionLocal()
    try:
        tenant = Tenant(name="Integration Tenant", slug="integration-tenant")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        admin = User(tenant_id=tenant.id, email="admin@integration.example.com", password_hash=_hasher.hash("pw"), role=ADMIN)
        db.add(admin)
        db.commit()
        tenant_id = tenant.id
    finally:
        db.close()

    login = client.post("/api/v1/auth/login", json={"email": "admin@integration.example.com", "password": "pw"})
    assert login.status_code == 200, login.json()
    admin_token = login.json()["access_token"]

    created = client.post(
        f"/api/v1/ingest/tenants/{tenant_id}/sensor-tokens",
        json={"name": "integration test sensor"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert created.status_code == 201, created.json()
    return created.json()["token"]


def _make_ingest_fn(client: TestClient, sensor_token: str):
    """Routes process_batch's ingest_fn through the real ingest endpoint
    via TestClient (in-process ASGI call, no real network socket) --
    the same contract api/kafka_sink.py's real _ingest_via_api has:
    raise on a whole-batch failure, return {"accepted", "failed"} on
    success."""

    def _fn(alert_dicts):
        resp = client.post(
            "/api/v1/ingest/alerts", json=alert_dicts, headers={"Authorization": f"Bearer {sensor_token}"}
        )
        resp.raise_for_status()
        return resp.json()

    return _fn


def _kafka_message(alert_id, **overrides):
    msg = {
        "alert_id": alert_id,
        "timestamp": "2026-09-06T00:00:00Z",
        "event_type": "dns",
        "threat_class": "DGA",
        "severity": "high",
        "confidence_score": 0.97,
        "source_ip": "10.0.0.5",
        "destination_ip": "8.8.8.8",
        "evidence": {"domain": "bad-example.biz"},
    }
    msg.update(overrides)
    return msg


def test_ingested_alert_is_readable_through_the_authenticated_api():
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        offsets = process_batch([(_kafka_message("ALT-int-1"), "tp0", 0)], ingest_fn=_make_ingest_fn(client, sensor_token))
        assert offsets == {"tp0": 1}

        # The static service key holds every scope and no tenant_id --
        # it sees every tenant's data, same as before tenants existed.
        r = client.get("/api/v1/alerts", headers=AUTH_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["alert_id"] == "ALT-int-1"
        assert body[0]["threat_class"] == "DGA"
        assert body[0]["severity"] == "high"


def test_ingested_alert_is_readable_by_id():
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        process_batch(
            [(_kafka_message("ALT-int-2", threat_class="RECON_PORT_SCAN"), "tp0", 0)],
            ingest_fn=_make_ingest_fn(client, sensor_token),
        )

        r = client.get("/api/v1/alerts/ALT-int-2", headers=AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json()["threat_class"] == "RECON_PORT_SCAN"

        r_missing = client.get("/api/v1/alerts/ALT-does-not-exist", headers=AUTH_HEADERS)
        assert r_missing.status_code == 404


def test_cursor_pagination_round_trip_through_the_real_endpoint():
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        batch = [(_kafka_message(f"ALT-int-page-{i}"), "tp0", i) for i in range(3)]
        process_batch(batch, ingest_fn=_make_ingest_fn(client, sensor_token))

        first_page = client.get("/api/v1/alerts", params={"limit": 2}, headers=AUTH_HEADERS).json()
        assert len(first_page) == 2
        # order_by(Alert.id.desc()): most-recently-inserted row comes first.
        assert first_page[0]["alert_id"] == "ALT-int-page-2"

        cursor = first_page[-1]["id"]
        second_page = client.get(
            "/api/v1/alerts",
            params={"limit": 2, "cursor": cursor},
            headers=AUTH_HEADERS,
        ).json()
        assert len(second_page) == 1
        assert second_page[0]["alert_id"] == "ALT-int-page-0"

        seen_ids = {a["alert_id"] for a in first_page + second_page}
        assert seen_ids == {"ALT-int-page-0", "ALT-int-page-1", "ALT-int-page-2"}


def test_a_message_the_pipeline_rejects_never_becomes_visible_through_the_api():
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        # Missing every required AlertPayload field (alert_id, event_type,
        # timestamp, threat_class, severity, confidence_score, source_ip) --
        # process_batch must route it to the DLQ path, never calling ingest_fn.
        bad_message = {"garbage": "not a real alert"}
        offsets = process_batch([(bad_message, "tp0", 0)], ingest_fn=_make_ingest_fn(client, sensor_token))
        assert offsets == {"tp0": 1}  # offset still advances past the poison message

        r = client.get("/api/v1/alerts", headers=AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == []


def test_unauthenticated_caller_gets_401_even_with_real_data_present():
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        process_batch([(_kafka_message("ALT-int-secret"), "tp0", 0)], ingest_fn=_make_ingest_fn(client, sensor_token))

        r = client.get("/api/v1/alerts")
        assert r.status_code == 401
        assert "ALT-int-secret" not in r.text


def test_reingesting_the_same_alert_id_updates_rather_than_duplicates():
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        ingest_fn = _make_ingest_fn(client, sensor_token)
        process_batch([(_kafka_message("ALT-int-dedup", severity="low"), "tp0", 0)], ingest_fn=ingest_fn)
        process_batch([(_kafka_message("ALT-int-dedup", severity="critical"), "tp0", 1)], ingest_fn=ingest_fn)

        r = client.get("/api/v1/alerts", headers=AUTH_HEADERS)
        matches = [a for a in r.json() if a["alert_id"] == "ALT-int-dedup"]
        assert len(matches) == 1
        assert matches[0]["severity"] == "critical"


def test_ingested_alert_is_tagged_with_the_sensors_tenant():
    """The property that actually motivated moving ingestion behind this
    endpoint: an alert lands scoped to the sensor's own tenant, not
    unscoped or attributable to whichever tenant asks first."""
    with TestClient(app) as client:
        sensor_token = _provision_sensor_token(client)
        process_batch([(_kafka_message("ALT-int-tenant-1"), "tp0", 0)], ingest_fn=_make_ingest_fn(client, sensor_token))

    db = SessionLocal()
    try:
        stored = db.query(Alert).filter(Alert.alert_id == "ALT-int-tenant-1").first()
        tenant = db.query(Tenant).filter(Tenant.slug == "integration-tenant").first()
        assert stored.tenant_id == tenant.id
    finally:
        db.close()
