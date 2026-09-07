"""scripts/bootstrap_tenant.py: the CLI wrapper around the two real API
calls (signup, then mint a sensor token) that get a brand-new tenant
past the auth system's chicken-and-egg problem. The endpoints
themselves are already covered by tests/unit/test_auth_routes.py's
TestSignup and tests/unit/test_ingest_routes.py's TestSensorTokenCreation
-- these tests are about the script's own control flow (request
shapes, the 409 short-circuit, the printed output), so requests.post is
mocked rather than hitting a live server.
"""
import sys
from unittest.mock import MagicMock, patch

import scripts.bootstrap_tenant as bootstrap


def _signup_response(status_code=201, tenant_id=42, token="admin-jwt"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"access_token": token, "token_type": "bearer", "tenant_id": tenant_id}
    resp.raise_for_status.side_effect = None
    return resp


def _sensor_response(token="sensor-token-value"):
    resp = MagicMock()
    resp.status_code = 201
    resp.json.return_value = {"id": 1, "name": "Local dev sensor", "token": token}
    resp.raise_for_status.side_effect = None
    return resp


def _run(argv):
    with patch.object(sys, "argv", ["bootstrap_tenant.py"] + argv):
        return bootstrap.main()


class TestBootstrapTenant:
    def test_happy_path_signs_up_then_mints_a_sensor_token(self, capsys):
        with patch(
            "scripts.bootstrap_tenant.requests.post",
            side_effect=[_signup_response(), _sensor_response()],
        ) as mock_post:
            exit_code = _run(["--tenant-name", "Acme Corp", "--email", "admin@acme.example.com", "--password", "correct-horse"])

        assert exit_code == 0
        assert mock_post.call_count == 2

        signup_args, signup_kwargs = mock_post.call_args_list[0]
        assert signup_args[0] == f"{bootstrap._DEFAULT_API_URL}/auth/signup"
        assert signup_kwargs["json"] == {
            "tenant_name": "Acme Corp",
            "email": "admin@acme.example.com",
            "password": "correct-horse",
        }

        sensor_args, sensor_kwargs = mock_post.call_args_list[1]
        assert sensor_args[0] == f"{bootstrap._DEFAULT_API_URL}/ingest/tenants/42/sensor-tokens"
        assert sensor_kwargs["headers"] == {"Authorization": "Bearer admin-jwt"}

        out = capsys.readouterr().out
        assert "TSOC_SENSOR_TOKEN=sensor-token-value" in out
        assert "admin@acme.example.com" in out
        # An explicitly-passed password is never echoed back.
        assert "correct-horse" not in out

    def test_generates_a_password_when_none_given_and_prints_it_once(self, capsys):
        with patch(
            "scripts.bootstrap_tenant.requests.post",
            side_effect=[_signup_response(), _sensor_response()],
        ) as mock_post:
            exit_code = _run(["--tenant-name", "Acme Corp", "--email", "admin@acme.example.com"])

        assert exit_code == 0
        signup_kwargs = mock_post.call_args_list[0].kwargs
        generated_password = signup_kwargs["json"]["password"]
        assert len(generated_password) > 8

        out = capsys.readouterr().out
        assert generated_password in out  # only shown because it was auto-generated

    def test_a_duplicate_email_fails_fast_without_attempting_the_sensor_token_call(self, capsys):
        with patch("scripts.bootstrap_tenant.requests.post", return_value=_signup_response(status_code=409)) as mock_post:
            exit_code = _run(["--email", "already-exists@example.com"])

        assert exit_code == 1
        assert mock_post.call_count == 1  # never reached the sensor-token call
        assert "already exists" in capsys.readouterr().err

    def test_custom_api_url_is_used_for_both_calls(self):
        custom_url = "https://api.tsoc.example/api/v1"
        with patch(
            "scripts.bootstrap_tenant.requests.post",
            side_effect=[_signup_response(), _sensor_response()],
        ) as mock_post:
            _run(["--api-url", custom_url])

        assert mock_post.call_args_list[0].args[0].startswith(custom_url)
        assert mock_post.call_args_list[1].args[0].startswith(custom_url)
