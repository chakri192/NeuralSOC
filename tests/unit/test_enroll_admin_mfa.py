"""scripts/enroll_admin_mfa.py: the CLI wrapper around login -> enroll ->
confirm. The endpoints themselves are already covered by
tests/unit/test_mfa.py -- these tests are about the script's own control
flow and printed output, so requests.post/input/getpass are mocked
rather than hitting a live server.
"""
import sys
from unittest.mock import MagicMock, patch

import scripts.enroll_admin_mfa as enroll_script


def _login_response(status_code=200, mfa_required=False, token="admin-jwt"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"mfa_required": mfa_required, "access_token": token, "tenant_id": 1}
    resp.raise_for_status.side_effect = None
    return resp


def _enroll_response(status_code=200, secret="JBSWY3DPEHPK3PXP", uri="otpauth://totp/T-SOC:admin?secret=JBSWY3DPEHPK3PXP"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"secret": secret, "otpauth_uri": uri}
    resp.raise_for_status.side_effect = None
    return resp


def _confirm_response(status_code=204):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = "" if status_code == 204 else "Invalid code"
    return resp


def _run(argv):
    with patch.object(sys, "argv", ["enroll_admin_mfa.py"] + argv):
        return enroll_script.main()


class TestEnrollAdminMfa:
    def test_happy_path_logs_in_enrolls_and_confirms(self, capsys):
        with patch(
            "scripts.enroll_admin_mfa.requests.post",
            side_effect=[_login_response(), _enroll_response(), _confirm_response()],
        ) as mock_post, patch("builtins.input", return_value="123456"):
            exit_code = _run(["--email", "admin@acme.example.com", "--password", "correct-horse"])

        assert exit_code == 0
        assert mock_post.call_count == 3

        login_args, login_kwargs = mock_post.call_args_list[0]
        assert login_args[0] == f"{enroll_script._DEFAULT_API_URL}/auth/login"
        assert login_kwargs["json"] == {"email": "admin@acme.example.com", "password": "correct-horse"}

        enroll_args, enroll_kwargs = mock_post.call_args_list[1]
        assert enroll_args[0] == f"{enroll_script._DEFAULT_API_URL}/auth/mfa/enroll"
        assert enroll_kwargs["headers"] == {"Authorization": "Bearer admin-jwt"}

        confirm_args, confirm_kwargs = mock_post.call_args_list[2]
        assert confirm_args[0] == f"{enroll_script._DEFAULT_API_URL}/auth/mfa/confirm"
        assert confirm_kwargs["json"] == {"code": "123456"}

        out = capsys.readouterr().out
        assert "JBSWY3DPEHPK3PXP" in out
        assert "now enabled" in out

    def test_wrong_confirmation_code_fails_without_claiming_success(self, capsys):
        with patch(
            "scripts.enroll_admin_mfa.requests.post",
            side_effect=[_login_response(), _enroll_response(), _confirm_response(status_code=400)],
        ), patch("builtins.input", return_value="000000"):
            exit_code = _run(["--email", "admin@acme.example.com", "--password", "correct-horse"])

        assert exit_code == 1
        assert "NOT enabled" in capsys.readouterr().err

    def test_refuses_to_re_enroll_an_already_mfa_enabled_account(self, capsys):
        with patch("scripts.enroll_admin_mfa.requests.post", return_value=_login_response(mfa_required=True)) as mock_post:
            exit_code = _run(["--email", "admin@acme.example.com", "--password", "correct-horse"])

        assert exit_code == 1
        assert mock_post.call_count == 1  # never reached enroll
        assert "already enabled" in capsys.readouterr().err

    def test_non_admin_account_is_rejected_by_the_api_and_reported_clearly(self, capsys):
        forbidden = MagicMock()
        forbidden.status_code = 403
        with patch(
            "scripts.enroll_admin_mfa.requests.post", side_effect=[_login_response(), forbidden]
        ):
            exit_code = _run(["--email", "analyst@acme.example.com", "--password", "correct-horse"])

        assert exit_code == 1
        assert "admin-only" in capsys.readouterr().err

    def test_password_is_prompted_for_when_not_passed_on_the_command_line(self):
        with patch(
            "scripts.enroll_admin_mfa.requests.post",
            side_effect=[_login_response(), _enroll_response(), _confirm_response()],
        ) as mock_post, patch("builtins.input", return_value="123456"), \
             patch("scripts.enroll_admin_mfa.getpass.getpass", return_value="typed-interactively") as mock_getpass:
            _run(["--email", "admin@acme.example.com"])

        mock_getpass.assert_called_once()
        login_kwargs = mock_post.call_args_list[0].kwargs
        assert login_kwargs["json"]["password"] == "typed-interactively"
