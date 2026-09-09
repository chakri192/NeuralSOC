"""dashboard/pages/admin.py: the first UI for invite/deactivate/sensor-
tokens/MFA/audit-log -- previously CLI-only (scripts/bootstrap_tenant.py,
scripts/enroll_admin_mfa.py), a real blocker for a company that wants
someone other than whoever has server access to manage their team.

Same AppTest pattern as tests/unit/test_dashboard_pages.py, mocking
requests.get/requests.post directly rather than session_data (this page
talks to the API on its own, not through session_data.py).
"""
from unittest.mock import MagicMock, patch

from streamlit.testing.v1 import AppTest

_ME_ADMIN = {
    "id": 1, "email": "admin@acme.example.com", "role": "admin", "tenant_id": 7,
    "mfa_enabled": False, "is_active": True, "created_at": "2026-01-01T00:00:00", "last_login_at": None,
}
_USERS = [
    {"id": 1, "email": "admin@acme.example.com", "role": "admin", "is_active": True, "created_at": "2026-01-01T00:00:00", "last_login_at": None},
    {"id": 2, "email": "teammate@acme.example.com", "role": "analyst", "is_active": True, "created_at": "2026-01-02T00:00:00", "last_login_at": None},
]
_TOKENS = [
    {"id": 1, "name": "HQ sensor", "is_active": True, "created_at": "2026-01-01T00:00:00", "last_used_at": ""},
]
_AUDIT = [
    {"id": 1, "action": "login.success", "actor_label": "admin@acme.example.com", "target": None, "detail": None, "created_at": "2026-01-01T00:00:00"},
]


def _mock_response(json_body, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.raise_for_status.side_effect = None
    return resp


def _get_side_effect(path, **kwargs):
    if path.endswith("/auth/me"):
        return _mock_response(_ME_ADMIN)
    if "/users" in path:
        return _mock_response(_USERS)
    if "/sensor-tokens" in path:
        return _mock_response(_TOKENS)
    if path.endswith("/audit"):
        return _mock_response(_AUDIT)
    raise AssertionError(f"unexpected GET {path}")


def _run_admin_page(role="admin", get_side_effect=None):
    at = AppTest.from_file("dashboard/pages/admin.py", default_timeout=15)
    at.session_state["access_token"] = "admin-jwt"
    at.session_state["role"] = role
    at.session_state["tenant_id"] = 7
    with patch("requests.get", side_effect=get_side_effect or _get_side_effect):
        at.run()
    return at


class TestAccessControl:
    def test_non_admin_sees_a_restricted_message_and_makes_no_api_calls(self):
        with patch("requests.get") as mock_get:
            at = AppTest.from_file("dashboard/pages/admin.py", default_timeout=15)
            at.session_state["access_token"] = "analyst-jwt"
            at.session_state["role"] = "analyst"
            at.session_state["tenant_id"] = 7
            at.run()
        mock_get.assert_not_called()
        assert not at.exception
        assert any("admin" in w.value.lower() for w in at.warning)


class TestLoadsSuccessfully:
    def test_renders_all_four_tabs_without_exception(self):
        at = _run_admin_page()
        assert not at.exception
        text = "\n".join(m.value for m in at.markdown)
        assert "Team & Access" in text


class TestInvite:
    def test_submitting_the_invite_form_calls_the_right_endpoint(self):
        at = _run_admin_page()
        email_input = [w for w in at.text_input if w.label == "Email"][0]
        email_input.set_value("newperson@acme.example.com")
        role_select = [w for w in at.selectbox if w.label == "Role"][0]
        role_select.select("analyst")
        invite_button = [b for b in at.button if b.label == "Send invite"][0]

        with patch("requests.get", side_effect=_get_side_effect), \
             patch("requests.post", return_value=_mock_response({"id": 3, "email": "newperson@acme.example.com", "role": "analyst"}, 201)) as mock_post:
            invite_button.click().run()

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0].endswith("/auth/tenants/7/users/invite")
        assert kwargs["json"] == {"email": "newperson@acme.example.com", "role": "analyst"}
        assert kwargs["headers"] == {"Authorization": "Bearer admin-jwt"}


class TestSensorTokens:
    def test_creating_a_token_shows_it_exactly_once(self):
        at = _run_admin_page()
        label_input = [w for w in at.text_input if w.label == "Label"][0]
        label_input.set_value("Branch office sensor")
        create_button = [b for b in at.button if b.label == "Create token"][0]

        with patch("requests.get", side_effect=_get_side_effect), \
             patch("requests.post", return_value=_mock_response({"id": 2, "name": "Branch office sensor", "token": "sekrit-token-value"}, 201)):
            at = create_button.click().run()

        assert not at.exception
        codes = [c.value for c in at.get("code")]
        assert "sekrit-token-value" in codes


class TestMfaEnrollment:
    def test_start_enrollment_shows_the_secret_and_uri(self):
        at = _run_admin_page()
        start_button = [b for b in at.button if b.label == "Start enrollment"][0]

        with patch("requests.get", side_effect=_get_side_effect), \
             patch("requests.post", return_value=_mock_response({"secret": "JBSWY3DPEHPK3PXP", "otpauth_uri": "otpauth://totp/x"}, 200)):
            at = start_button.click().run()

        assert not at.exception
        codes = [c.value for c in at.get("code")]
        assert "JBSWY3DPEHPK3PXP" in codes
        assert "otpauth://totp/x" in codes

    def test_already_enabled_account_shows_a_disable_form_instead(self):
        me_with_mfa = {**_ME_ADMIN, "mfa_enabled": True}

        def _get_mfa_enabled(path, **kwargs):
            if path.endswith("/auth/me"):
                return _mock_response(me_with_mfa)
            return _get_side_effect(path, **kwargs)

        at = _run_admin_page(get_side_effect=_get_mfa_enabled)
        assert not at.exception
        assert any("MFA is enabled" in s.value for s in at.success)


class TestAuditLog:
    def test_renders_recorded_events(self):
        at = _run_admin_page()
        assert not at.exception
        assert len(at.dataframe) >= 1
