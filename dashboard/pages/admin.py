"""Admin-only settings: team management, sensor tokens, this account's
own MFA, and the audit log. Only reachable via nav for role=admin
sessions (dashboard/app.py builds the page list from
st.session_state["role"]) -- but every API call below is independently
enforced server-side (require_scope("users:manage")) regardless, so
this page guards UX, not security.

Deliberately built entirely on Streamlit's own widgets (st.dataframe,
st.code) rather than hand-rolled HTML via unsafe_allow_html=True, unlike
command_center.py/investigate.py -- those pages render attacker-
influenced network telemetry and need explicit escaping (see
shared/formatters.py's ATTACKER_INFLUENCED_ALERT_FIELDS); this page
only ever renders admin-entered account/sensor metadata through widgets
that already escape by default, so there's no unsafe_allow_html call in
this file to get wrong.
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pandas as pd
import requests
import streamlit as st

_API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1")
_REQUEST_TIMEOUT_SEC = 8
# Mirrors api/models.py's VALID_ROLES -- duplicated as literal strings
# rather than imported, since dashboard/'s own Docker image
# (Dockerfile.dashboard) never includes api/ in its build context at
# all (see Dockerfile.dashboard.dockerignore).
_VALID_ROLES = ["analyst", "lead", "admin"]

if st.session_state.get("role") != "admin":
    st.warning("This page is only available to tenant admins.")
    st.stop()

_token = st.session_state["access_token"]
_tenant_id = st.session_state["tenant_id"]
_headers = {"Authorization": f"Bearer {_token}"}


def _get(path: str):
    resp = requests.get(f"{_API_URL}{path}", headers=_headers, timeout=_REQUEST_TIMEOUT_SEC)
    resp.raise_for_status()
    return resp.json()


def _post(path: str, json: dict = None):
    resp = requests.post(f"{_API_URL}{path}", json=json or {}, headers=_headers, timeout=_REQUEST_TIMEOUT_SEC)
    return resp


st.markdown("## Team & Access")
st.caption("Invite teammates, manage sensor tokens, and secure this account -- admin-only.")

try:
    me = _get("/auth/me")
except requests.RequestException as ex:
    st.error(f"Could not reach the T-SOC API: {ex}")
    st.stop()

tab_team, tab_sensors, tab_security, tab_audit = st.tabs(["Team", "Sensor Tokens", "Security", "Audit Log"])

# ---------- Team ----------
with tab_team:
    try:
        users = _get(f"/auth/tenants/{_tenant_id}/users")
    except requests.RequestException as ex:
        st.error(f"Could not load the team list: {ex}")
        users = []

    if users:
        df = pd.DataFrame(users)[["email", "role", "is_active", "last_login_at"]]
        df.columns = ["Email", "Role", "Active", "Last login"]
        st.dataframe(df, hide_index=True, width="stretch")

        deactivatable = [u for u in users if u["is_active"] and u["id"] != me["id"]]
        if deactivatable:
            with st.expander("Deactivate a teammate"):
                target = st.selectbox(
                    "Account", deactivatable, format_func=lambda u: f"{u['email']} ({u['role']})", key="deactivate_target"
                )
                if st.button("Deactivate", type="primary"):
                    r = _post(f"/auth/tenants/{_tenant_id}/users/{target['id']}/deactivate")
                    if r.status_code == 204:
                        st.toast(f"Deactivated {target['email']}", icon=":material/check_circle:")
                        st.rerun()
                    else:
                        st.error(f"Could not deactivate: {r.json().get('detail', r.status_code)}")

    st.markdown("#### Invite a teammate")
    with st.form("invite_form", clear_on_submit=True):
        invite_email = st.text_input("Email")
        invite_role = st.selectbox("Role", sorted(_VALID_ROLES))
        invited = st.form_submit_button("Send invite", type="primary")
    if invited:
        if not invite_email.strip():
            st.error("Enter an email address.")
        else:
            r = _post(f"/auth/tenants/{_tenant_id}/users/invite", json={"email": invite_email.strip(), "role": invite_role})
            if r.status_code == 201:
                st.success(f"Invited {invite_email.strip()}. They'll receive an email with a link to set their password.")
            else:
                st.error(f"Could not send the invite: {r.json().get('detail', r.status_code)}")

# ---------- Sensor tokens ----------
with tab_sensors:
    st.caption("Each on-prem collector authenticates with its own token -- never share one across sites.")
    try:
        tokens = _get(f"/ingest/tenants/{_tenant_id}/sensor-tokens")
    except requests.RequestException as ex:
        st.error(f"Could not load sensor tokens: {ex}")
        tokens = []

    if tokens:
        df = pd.DataFrame(tokens)[["name", "is_active", "created_at", "last_used_at"]]
        df.columns = ["Name", "Active", "Created", "Last used"]
        st.dataframe(df, hide_index=True, width="stretch")

    st.markdown("#### Mint a new sensor token")
    with st.form("sensor_form", clear_on_submit=True):
        sensor_name = st.text_input("Label", placeholder="e.g. HQ data diode")
        minted = st.form_submit_button("Create token", type="primary")
    if minted:
        if not sensor_name.strip():
            st.error("Enter a label for this sensor.")
        else:
            r = _post(f"/ingest/tenants/{_tenant_id}/sensor-tokens", json={"name": sensor_name.strip()})
            if r.status_code == 201:
                st.warning("This token is shown once and can't be retrieved again -- copy it now.")
                st.code(r.json()["token"], language=None)
                st.caption("Set it as TSOC_SENSOR_TOKEN wherever api/kafka_sink.py runs for this site.")
            else:
                st.error(f"Could not create the token: {r.json().get('detail', r.status_code)}")

# ---------- Security (own MFA) ----------
with tab_security:
    st.caption("TOTP MFA is admin-only and opt-in -- this controls your own account, not your teammates'.")
    if me["mfa_enabled"]:
        st.success("MFA is enabled on your account.")
        with st.form("mfa_disable_form"):
            disable_code = st.text_input("Current 6-digit code, to confirm disabling MFA", max_chars=6)
            disable_submitted = st.form_submit_button("Disable MFA")
        if disable_submitted:
            r = _post("/auth/mfa/disable", json={"code": disable_code.strip()})
            if r.status_code == 204:
                st.toast("MFA disabled.", icon=":material/check_circle:")
                st.rerun()
            else:
                st.error("Incorrect code.")
    else:
        st.info("MFA is not enabled on your account.")
        if "_mfa_enroll_secret" not in st.session_state:
            if st.button("Start enrollment", type="primary"):
                r = _post("/auth/mfa/enroll")
                if r.status_code == 200:
                    st.session_state["_mfa_enroll_secret"] = r.json()["secret"]
                    st.session_state["_mfa_enroll_uri"] = r.json()["otpauth_uri"]
                    st.rerun()
                else:
                    st.error("Could not start enrollment.")
        else:
            st.write("Scan this with an authenticator app (Google Authenticator, 1Password, etc.), or add the secret manually:")
            st.code(st.session_state["_mfa_enroll_uri"], language=None)
            st.code(st.session_state["_mfa_enroll_secret"], language=None)
            with st.form("mfa_confirm_form"):
                confirm_code = st.text_input("6-digit code from your authenticator app", max_chars=6)
                confirm_submitted = st.form_submit_button("Confirm & enable MFA", type="primary")
            if confirm_submitted:
                r = _post("/auth/mfa/confirm", json={"code": confirm_code.strip()})
                if r.status_code == 204:
                    st.session_state.pop("_mfa_enroll_secret", None)
                    st.session_state.pop("_mfa_enroll_uri", None)
                    st.toast("MFA enabled.", icon=":material/check_circle:")
                    st.rerun()
                else:
                    st.error("That code didn't match -- try again.")
            if st.button("Cancel enrollment"):
                st.session_state.pop("_mfa_enroll_secret", None)
                st.session_state.pop("_mfa_enroll_uri", None)
                st.rerun()

# ---------- Audit log ----------
with tab_audit:
    try:
        entries = _get("/audit")
    except requests.RequestException as ex:
        st.error(f"Could not load the audit log: {ex}")
        entries = []

    if not entries:
        st.info("No audit events recorded yet.")
    else:
        df = pd.DataFrame(entries)[["created_at", "action", "actor_label", "target", "detail"]]
        df.columns = ["When", "Action", "Actor", "Target", "Detail"]
        st.dataframe(df, hide_index=True, width="stretch")
