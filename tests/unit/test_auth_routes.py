"""api/routes/auth.py: login/logout/password-reset/invite, built on the
JWT toolkit (api/auth.py) and scope enforcement (api/deps.py) that
existed before but were never wired up to a real caller. Uses a fake
Redis (matching tests/conftest.py's existing fakeredis pattern for
inference.correlation) so lockout/revocation exercise real logic
instead of the fail-open fallback that kicks in when Redis is
genuinely unreachable.
"""
import os
import urllib.parse
from unittest.mock import patch

import fakeredis
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

import api.deps as deps
import api.routes.auth as auth_routes
from api.auth import verify_token
from api.database import Base, SessionLocal, engine
from api.main import app
from api.models import ADMIN, ANALYST, ROLE_SCOPES, Tenant, User

_hasher = PasswordHasher()

Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def _isolated_redis(monkeypatch):
    # FastAPI runs a sync `def` route (login) in an anyio worker-thread
    # pool, whose threads get reused across requests -- and reused across
    # tests, since TestClient(app) doesn't tear that pool down. A
    # FakeStrictRedis() with no explicit `server=` falls back to an
    # implicit default lookup that (empirically, not per fakeredis's
    # documented isolation guarantees) can resolve to the same backing
    # server when invoked from the same worker thread twice, even from
    # two entirely separate Python objects -- passing a distinct
    # FakeServer() removes any implicit lookup for it to share.
    fake = fakeredis.FakeStrictRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(deps, "get_redis_client", lambda: fake)
    yield fake


@pytest.fixture(autouse=True)
def _disable_rate_limiter():
    """login is real-rate-limited (10/minute, see api/routes/auth.py) --
    that's already covered by tests/test_api_endpoints.py's own dedicated
    rate-limit test. These tests are about login/lockout/token logic, not
    the rate limiter itself, and collectively make far more than 10 login
    calls across the file -- disable it here rather than trying to keep
    every test under a shared process-wide budget it isn't testing."""
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


@pytest.fixture
def sent_emails(monkeypatch):
    captured = []
    monkeypatch.setattr(auth_routes, "_deliver_email", lambda to, subject, link: captured.append((to, subject, link)))
    return captured


def _create_user(email="analyst@example.com", password="correct-horse-battery", role=ANALYST, is_active=True, tenant_slug="acme"):
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            tenant = Tenant(name="Acme Corp", slug=tenant_slug)
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
        user = User(
            tenant_id=tenant.id,
            email=email,
            password_hash=_hasher.hash(password),
            role=role,
            is_active=is_active,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id, tenant.id
    finally:
        db.close()


def _extract_token(link: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(link).query)["token"][0]


def _login(client, email, password="correct-horse-battery"):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


class TestDeliverEmail:
    """_deliver_email() itself, not through a full invite/reset route --
    the fallback-to-stub and swallow-a-real-failure behavior that lets
    every other test in this file keep mocking it wholesale via the
    sent_emails fixture without needing real SMTP configured."""

    def test_falls_back_to_logging_when_smtp_is_not_configured(self, monkeypatch, caplog):
        monkeypatch.setattr("api.email.SMTP_HOST", None)
        with patch("api.routes.auth.send_email") as mock_send:
            auth_routes._deliver_email("a@x.com", "subject", "https://example.com/link")
        mock_send.assert_not_called()
        assert "STUB EMAIL" in caplog.text

    def test_sends_for_real_when_smtp_is_configured(self, monkeypatch):
        monkeypatch.setattr("api.email.SMTP_HOST", "smtp.example.com")
        with patch("api.routes.auth.send_email") as mock_send:
            auth_routes._deliver_email("a@x.com", "subject", "https://example.com/link")
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == "a@x.com"
        assert args[1] == "subject"
        assert "https://example.com/link" in args[2]

    def test_a_real_send_failure_is_logged_and_swallowed_not_raised(self, monkeypatch, caplog):
        monkeypatch.setattr("api.email.SMTP_HOST", "smtp.example.com")
        with patch("api.routes.auth.send_email", side_effect=ConnectionRefusedError("no route to host")):
            auth_routes._deliver_email("a@x.com", "subject", "https://example.com/link")  # must not raise
        assert "Failed to send email" in caplog.text


class TestSignup:
    def test_creates_a_new_tenant_and_admin_and_returns_a_working_token(self):
        with TestClient(app) as client:
            r = client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Acme Corp", "email": "founder@acme.example.com", "password": "correct-horse"},
            )
        assert r.status_code == 201
        payload = verify_token(r.json()["access_token"])
        assert set(payload["scopes"]) == set(ROLE_SCOPES[ADMIN])
        assert payload["tenant_id"] is not None

        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.id == payload["tenant_id"]).first()
            assert tenant.name == "Acme Corp"
            assert tenant.slug  # non-empty, derived from the name
            user = db.query(User).filter(User.id == payload["user_id"]).first()
            assert user.role == ADMIN
            assert user.is_active is True  # no invite link to accept -- they set this password themselves
        finally:
            db.close()

    def test_created_admin_can_immediately_log_in(self):
        with TestClient(app) as client:
            client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Acme Corp", "email": "founder@acme.example.com", "password": "correct-horse"},
            )
            r = client.post("/api/v1/auth/login", json={"email": "founder@acme.example.com", "password": "correct-horse"})
        assert r.status_code == 200

    def test_rejects_a_duplicate_email(self):
        with TestClient(app) as client:
            client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Acme Corp", "email": "founder@acme.example.com", "password": "correct-horse"},
            )
            r = client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Globex", "email": "founder@acme.example.com", "password": "another-password"},
            )
        assert r.status_code == 409

    def test_rejects_a_password_shorter_than_the_minimum(self):
        with TestClient(app) as client:
            r = client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Acme Corp", "email": "founder@acme.example.com", "password": "short"},
            )
        assert r.status_code == 422

    def test_rejects_an_empty_tenant_name(self):
        with TestClient(app) as client:
            r = client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "   ", "email": "founder@acme.example.com", "password": "correct-horse"},
            )
        assert r.status_code == 422

    def test_two_tenants_with_the_same_name_get_distinct_slugs(self):
        with TestClient(app) as client:
            client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Acme Corp", "email": "a@acme.example.com", "password": "correct-horse"},
            )
            client.post(
                "/api/v1/auth/signup",
                json={"tenant_name": "Acme Corp", "email": "b@acme.example.com", "password": "correct-horse"},
            )
        db = SessionLocal()
        try:
            slugs = [t.slug for t in db.query(Tenant).filter(Tenant.name == "Acme Corp").all()]
        finally:
            db.close()
        assert len(slugs) == 2
        assert len(set(slugs)) == 2  # distinct, not a unique-constraint collision


class TestLogin:
    def test_succeeds_with_correct_credentials_and_returns_a_properly_shaped_token(self):
        user_id, tenant_id = _create_user(role=ADMIN)
        with TestClient(app) as client:
            r = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
        assert r.status_code == 200
        token = r.json()["access_token"]
        payload = verify_token(token)
        assert payload["user_id"] == user_id
        assert payload["tenant_id"] == tenant_id
        assert set(payload["scopes"]) == set(ROLE_SCOPES[ADMIN])

    def test_rejects_wrong_password(self):
        _create_user()
        with TestClient(app) as client:
            r = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "wrong"})
        assert r.status_code == 401

    def test_rejects_unknown_email_with_the_same_message_as_wrong_password(self):
        _create_user()
        with TestClient(app) as client:
            wrong_pw = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "wrong"})
            unknown = client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "wrong"})
        assert wrong_pw.status_code == unknown.status_code == 401
        assert wrong_pw.json()["detail"] == unknown.json()["detail"]

    def test_rejects_an_inactive_user(self):
        _create_user(is_active=False)
        with TestClient(app) as client:
            r = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
        assert r.status_code == 401

    def test_updates_last_login_at(self):
        user_id, _ = _create_user()
        with TestClient(app) as client:
            client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
        db = SessionLocal()
        try:
            assert db.get(User, user_id).last_login_at is not None
        finally:
            db.close()

    def test_locks_out_after_repeated_failures(self):
        _create_user()
        with TestClient(app) as client:
            statuses = [
                client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "wrong"}).status_code
                for _ in range(deps.LOGIN_LOCKOUT_MAX_ATTEMPTS + 1)
            ]
        assert statuses[:-1] == [401] * deps.LOGIN_LOCKOUT_MAX_ATTEMPTS
        assert statuses[-1] == 429

    def test_a_successful_login_clears_prior_failed_attempts(self):
        _create_user()
        with TestClient(app) as client:
            for _ in range(deps.LOGIN_LOCKOUT_MAX_ATTEMPTS - 1):
                client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "wrong"})
            good = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            assert good.status_code == 200
            # The counter should have been cleared, not just left one short of lockout.
            next_attempt = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "wrong"})
            assert next_attempt.status_code == 401


class TestLogout:
    def test_revokes_the_token_for_future_requests(self):
        _create_user()
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            token = login.json()["access_token"]

            before = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
            assert before.status_code == 200

            logout = client.post("/api/v1/auth/logout", json={"token": token})
            assert logout.status_code == 204

            after = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
            assert after.status_code == 401

    def test_logging_out_an_already_invalid_token_does_not_error(self):
        with TestClient(app) as client:
            r = client.post("/api/v1/auth/logout", json={"token": "not-a-real-token"})
        assert r.status_code == 204


class TestPasswordReset:
    def test_request_always_returns_the_same_response_whether_or_not_the_email_exists(self, sent_emails):
        _create_user()
        with TestClient(app) as client:
            known = client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
            unknown = client.post("/api/v1/auth/password-reset/request", json={"email": "nobody@example.com"})
        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()
        assert len(sent_emails) == 1  # only the real account actually got a link

    def test_confirm_end_to_end_changes_the_password(self, sent_emails):
        _create_user(password="old-password")
        with TestClient(app) as client:
            client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
            token = _extract_token(sent_emails[0][2])

            confirm = client.post("/api/v1/auth/password-reset/confirm", json={"token": token, "new_password": "new-password"})
            assert confirm.status_code == 204

            old_login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "old-password"})
            assert old_login.status_code == 401

            new_login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "new-password"})
            assert new_login.status_code == 200

    def test_confirm_token_is_single_use(self, sent_emails):
        _create_user(password="old-password")
        with TestClient(app) as client:
            client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
            token = _extract_token(sent_emails[0][2])

            first = client.post("/api/v1/auth/password-reset/confirm", json={"token": token, "new_password": "new-password"})
            assert first.status_code == 204

            replay = client.post("/api/v1/auth/password-reset/confirm", json={"token": token, "new_password": "another-password"})
            # confirm_password_reset checks is_token_revoked() itself (this
            # endpoint takes the token from the body, not the Authorization
            # header, so it never passes through verify_auth's own denylist
            # check) -- a consumed token is rejected the same way an
            # unrecognized one is.
            assert replay.status_code == 400

    def test_confirm_rejects_a_session_token_not_a_reset_token(self):
        _create_user()
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            session_token = login.json()["access_token"]
            r = client.post("/api/v1/auth/password-reset/confirm", json={"token": session_token, "new_password": "whatever"})
        assert r.status_code == 400

    def test_confirm_rejects_a_new_password_shorter_than_the_minimum(self, sent_emails):
        _create_user(password="old-password")
        with TestClient(app) as client:
            client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
            token = _extract_token(sent_emails[0][2])
            r = client.post("/api/v1/auth/password-reset/confirm", json={"token": token, "new_password": "short"})
        assert r.status_code == 422


class TestInviteUser:
    def test_requires_users_manage_scope(self):
        _, tenant_id = _create_user(role=ANALYST)
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            token = login.json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/invite",
                json={"email": "newperson@example.com", "role": "analyst"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 403

    def test_admin_cannot_invite_into_a_different_tenant(self):
        _, tenant_a_id = _create_user(email="admin@a.example.com", role=ADMIN, tenant_slug="tenant-a")
        _, tenant_b_id = _create_user(email="admin@b.example.com", role=ADMIN, tenant_slug="tenant-b")
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "admin@a.example.com", "password": "correct-horse-battery"})
            token = login.json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_b_id}/users/invite",
                json={"email": "newperson@example.com", "role": "analyst"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 403

    def test_admin_can_invite_a_new_teammate_who_starts_inactive(self, sent_emails):
        admin_id, tenant_id = _create_user(role=ADMIN)
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            token = login.json()["access_token"]
            invite = client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/invite",
                json={"email": "newperson@example.com", "role": "analyst"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert invite.status_code == 201
        assert invite.json()["role"] == "analyst"
        assert len(sent_emails) == 1

        db = SessionLocal()
        try:
            invited = db.query(User).filter(User.email == "newperson@example.com").first()
            assert invited.is_active is False
        finally:
            db.close()

    def test_accepting_an_invite_activates_the_account_and_allows_login(self, sent_emails):
        _, tenant_id = _create_user(role=ADMIN)
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            token = login.json()["access_token"]
            client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/invite",
                json={"email": "newperson@example.com", "role": "analyst"},
                headers={"Authorization": f"Bearer {token}"},
            )
            invite_token = _extract_token(sent_emails[0][2])

            not_yet = client.post("/api/v1/auth/login", json={"email": "newperson@example.com", "password": "chosen-password"})
            assert not_yet.status_code == 401

            accept = client.post(
                "/api/v1/auth/password-reset/confirm", json={"token": invite_token, "new_password": "chosen-password"}
            )
            assert accept.status_code == 204

            now_active = client.post("/api/v1/auth/login", json={"email": "newperson@example.com", "password": "chosen-password"})
            assert now_active.status_code == 200

    def test_rejects_duplicate_email(self, sent_emails):
        _, tenant_id = _create_user(role=ADMIN)
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery"})
            token = login.json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/invite",
                json={"email": "analyst@example.com", "role": "analyst"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 409


class TestGetMe:
    def test_returns_the_callers_own_profile(self):
        _create_user(email="admin@example.com", role=ADMIN)
        with TestClient(app) as client:
            token = _login(client, "admin@example.com").json()["access_token"]
            r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == "admin@example.com"
        assert body["role"] == ADMIN
        assert body["mfa_enabled"] is False
        assert body["is_active"] is True

    def test_the_static_service_key_has_no_profile_to_describe(self):
        with TestClient(app) as client:
            r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {os.environ['TSOC_API_KEY']}"})
        assert r.status_code == 400


class TestListUsers:
    def test_requires_users_manage_scope(self):
        _create_user(email="analyst@example.com", role=ANALYST)
        with TestClient(app) as client:
            token = _login(client, "analyst@example.com").json()["access_token"]
            r = client.get("/api/v1/auth/tenants/1/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_lists_only_the_callers_own_tenant(self):
        _, tenant_a = _create_user(email="admin@a.example.com", role=ADMIN, tenant_slug="tenant-a")
        _create_user(email="teammate@a.example.com", role=ANALYST, tenant_slug="tenant-a")
        _create_user(email="admin@b.example.com", role=ADMIN, tenant_slug="tenant-b")

        with TestClient(app) as client:
            token = _login(client, "admin@a.example.com").json()["access_token"]
            r = client.get(f"/api/v1/auth/tenants/{tenant_a}/users", headers={"Authorization": f"Bearer {token}"})

        assert r.status_code == 200
        emails = {row["email"] for row in r.json()}
        assert emails == {"admin@a.example.com", "teammate@a.example.com"}

    def test_admin_cannot_list_a_different_tenants_users(self):
        _, tenant_a = _create_user(email="admin@a.example.com", role=ADMIN, tenant_slug="tenant-a")
        _, tenant_b = _create_user(email="admin@b.example.com", role=ADMIN, tenant_slug="tenant-b")
        with TestClient(app) as client:
            token = _login(client, "admin@a.example.com").json()["access_token"]
            r = client.get(f"/api/v1/auth/tenants/{tenant_b}/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


class TestDeactivateUser:
    def test_requires_users_manage_scope(self):
        analyst_id, tenant_id = _create_user(email="analyst@example.com", role=ANALYST)
        with TestClient(app) as client:
            token = _login(client, "analyst@example.com").json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/{analyst_id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 403

    def test_admin_can_deactivate_a_teammate(self):
        admin_id, tenant_id = _create_user(email="admin@example.com", role=ADMIN)
        teammate_id, _ = _create_user(email="teammate@example.com", role=ANALYST, tenant_slug="acme")
        with TestClient(app) as client:
            token = _login(client, "admin@example.com").json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/{teammate_id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 204

        db = SessionLocal()
        try:
            teammate = db.query(User).filter(User.id == teammate_id).first()
            assert teammate.is_active is False
        finally:
            db.close()

    def test_a_deactivated_user_cannot_log_in_again(self):
        admin_id, tenant_id = _create_user(email="admin@example.com", role=ADMIN)
        teammate_id, _ = _create_user(email="teammate@example.com", role=ANALYST, tenant_slug="acme")
        with TestClient(app) as client:
            token = _login(client, "admin@example.com").json()["access_token"]
            client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/{teammate_id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
            )
            blocked = _login(client, "teammate@example.com")
        assert blocked.status_code == 401

    def test_admin_cannot_deactivate_their_own_account(self):
        admin_id, tenant_id = _create_user(email="admin@example.com", role=ADMIN)
        with TestClient(app) as client:
            token = _login(client, "admin@example.com").json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_id}/users/{admin_id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 400

    def test_admin_cannot_deactivate_a_user_in_a_different_tenant(self):
        admin_id, tenant_a = _create_user(email="admin@a.example.com", role=ADMIN, tenant_slug="tenant-a")
        other_id, tenant_b = _create_user(email="user@b.example.com", role=ANALYST, tenant_slug="tenant-b")
        with TestClient(app) as client:
            token = _login(client, "admin@a.example.com").json()["access_token"]
            r = client.post(
                f"/api/v1/auth/tenants/{tenant_b}/users/{other_id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 403
