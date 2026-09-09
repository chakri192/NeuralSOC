"""api/routes/auth.py's mfa_* endpoints: optional TOTP MFA, scoped to
admin accounts (Phase 6 ops hardening). Covers the enroll -> confirm ->
login-challenge -> verify lifecycle, disable, and the negative cases
that matter most for a second factor: a wrong code must never complete
login, and a non-admin must never be able to enroll at all.
"""
import fakeredis
import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
from api.database import Base, SessionLocal, engine
from api.main import app
from api.models import ADMIN, ANALYST, Tenant, User

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
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()
    yield


def _create_user(email="admin@acme.example.com", password="correct-horse-battery", role=ADMIN, tenant_slug="acme"):
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            tenant = Tenant(name="Acme Corp", slug=tenant_slug)
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
        user = User(tenant_id=tenant.id, email=email, password_hash=_hasher.hash(password), role=role, is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    finally:
        db.close()


def _login(client, email, password="correct-horse-battery"):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _enroll_and_confirm(client, token: str) -> str:
    """Enrolls and confirms MFA for the caller identified by `token`,
    returning the TOTP secret so a test can go on generating valid
    codes."""
    headers = {"Authorization": f"Bearer {token}"}
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert enroll.status_code == 200, enroll.json()
    secret = enroll.json()["secret"]
    code = pyotp.TOTP(secret).now()
    confirm = client.post("/api/v1/auth/mfa/confirm", json={"code": code}, headers=headers)
    assert confirm.status_code == 204, confirm.json()
    return secret


class TestEnrollment:
    def test_only_an_admin_can_enroll(self):
        _create_user(email="analyst@acme.example.com", role=ANALYST)
        with TestClient(app) as client:
            r = _login(client, "analyst@acme.example.com")
            token = r.json()["access_token"]
            enroll = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
        assert enroll.status_code == 403

    def test_enroll_returns_a_usable_otpauth_uri(self):
        _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            enroll = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
        assert enroll.status_code == 200
        body = enroll.json()
        assert body["otpauth_uri"].startswith("otpauth://totp/")
        assert "acme.example.com" in body["otpauth_uri"] or "%40" in body["otpauth_uri"]
        # The returned secret must actually be the one the URI encodes.
        assert pyotp.parse_uri(body["otpauth_uri"]).secret == body["secret"]

    def test_enrolling_before_confirming_does_not_enable_mfa(self):
        user_id = _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
            # A second login must still succeed as a plain login, with no
            # MFA challenge, until /mfa/confirm is called.
            r = _login(client, "admin@acme.example.com")
        assert r.json().get("mfa_required") is not True
        assert r.json()["access_token"]

        db = SessionLocal()
        user = db.query(User).filter(User.id == user_id).first()
        db.close()
        assert user.mfa_enabled is False

    def test_confirm_with_the_wrong_code_is_rejected(self):
        _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            client.post("/api/v1/auth/mfa/enroll", headers=headers)
            confirm = client.post("/api/v1/auth/mfa/confirm", json={"code": "000000"}, headers=headers)
        assert confirm.status_code == 400

    def test_confirm_actually_enables_mfa(self):
        user_id = _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            _enroll_and_confirm(client, token)

        db = SessionLocal()
        user = db.query(User).filter(User.id == user_id).first()
        db.close()
        assert user.mfa_enabled is True


class TestLoginWithMfa:
    def test_login_returns_a_challenge_not_a_token_once_mfa_is_enabled(self):
        _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            _enroll_and_confirm(client, token)
            r = _login(client, "admin@acme.example.com")

        body = r.json()
        assert body["mfa_required"] is True
        assert body["mfa_token"]
        assert body.get("access_token") is None

    def test_verify_with_the_correct_code_completes_login(self):
        _create_user()
        with TestClient(app) as client:
            first_token = _login(client, "admin@acme.example.com").json()["access_token"]
            secret = _enroll_and_confirm(client, first_token)
            challenge = _login(client, "admin@acme.example.com").json()
            code = pyotp.TOTP(secret).now()
            r = client.post("/api/v1/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": code})

        assert r.status_code == 200
        assert r.json()["access_token"]
        assert r.json()["tenant_id"] is not None

    def test_verify_with_the_wrong_code_is_rejected(self):
        _create_user()
        with TestClient(app) as client:
            first_token = _login(client, "admin@acme.example.com").json()["access_token"]
            _enroll_and_confirm(client, first_token)
            challenge = _login(client, "admin@acme.example.com").json()
            r = client.post("/api/v1/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": "000000"})
        assert r.status_code == 401

    def test_verify_token_is_single_use(self):
        _create_user()
        with TestClient(app) as client:
            first_token = _login(client, "admin@acme.example.com").json()["access_token"]
            secret = _enroll_and_confirm(client, first_token)
            challenge = _login(client, "admin@acme.example.com").json()
            code = pyotp.TOTP(secret).now()
            first = client.post("/api/v1/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": code})
            assert first.status_code == 200
            replay = client.post("/api/v1/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": code})
        assert replay.status_code == 401

    def test_a_stale_mfa_token_cannot_be_used_as_a_normal_bearer_token(self):
        """mfa_pending tokens carry no scopes -- even if presented as a
        normal Authorization header, they must not grant access to a
        scoped route."""
        _create_user()
        with TestClient(app) as client:
            first_token = _login(client, "admin@acme.example.com").json()["access_token"]
            _enroll_and_confirm(client, first_token)
            challenge = _login(client, "admin@acme.example.com").json()
            r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {challenge['mfa_token']}"})
        assert r.status_code == 403


class TestDisable:
    def test_disable_requires_a_correct_code(self):
        _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            secret = _enroll_and_confirm(client, token)
            headers = {"Authorization": f"Bearer {token}"}
            wrong = client.post("/api/v1/auth/mfa/disable", json={"code": "000000"}, headers=headers)
            assert wrong.status_code == 400
            right = client.post(
                "/api/v1/auth/mfa/disable", json={"code": pyotp.TOTP(secret).now()}, headers=headers
            )
        assert right.status_code == 204

    def test_disable_turns_off_the_login_challenge(self):
        user_id = _create_user()
        with TestClient(app) as client:
            token = _login(client, "admin@acme.example.com").json()["access_token"]
            secret = _enroll_and_confirm(client, token)
            client.post(
                "/api/v1/auth/mfa/disable",
                json={"code": pyotp.TOTP(secret).now()},
                headers={"Authorization": f"Bearer {token}"},
            )
            r = _login(client, "admin@acme.example.com")

        assert r.json().get("mfa_required") is not True
        assert r.json()["access_token"]

        db = SessionLocal()
        user = db.query(User).filter(User.id == user_id).first()
        db.close()
        assert user.mfa_enabled is False
        assert user.totp_secret is None
