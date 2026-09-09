import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests
import streamlit as st
import streamlit.components.v1 as components

from dashboard import session_data
from dashboard.components.icons import svg
from dashboard.components.ui import inject_theme, connection_pill

_API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1")

st.set_page_config(
    page_title="T-SOC Operations Center",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon=":material/security:",
)

inject_theme()
_is_authenticated = bool(st.session_state.get("access_token"))

# st.logo() renders into the sidebar's dedicated header slot, which is
# always the first thing in the sidebar regardless of call order --
# unlike markdown content placed inside the sidebar (which Streamlit
# always draws *after* st.navigation()'s own nav links, no matter where
# in the script it's written). It's the only way to put branding above
# the nav rather than sandwiched below it. Gated on auth: with no sidebar
# content to sit above yet, st.logo() falls back to painting itself in
# the main content area's top-left instead -- doubling up with the login
# card's own centered "T-SOC" mark rather than replacing it.
if _is_authenticated:
    st.logo(os.path.join(os.path.dirname(__file__), "assets", "brand.svg"), size="large")


# Defined and called unconditionally, before the auth check: the moment
# ANY session calls st.navigation(), Streamlit permanently stops falling
# back to auto-discovering dashboard/pages/*.py by filename (across every
# session, not just this one). Skipping this call while logged out --
# e.g. to avoid drawing nav the user hasn't earned yet -- is exactly what
# left that raw, un-gated file list (dev scripts included) showing in the
# sidebar during the login screen. position="hidden" suppresses the
# sidebar links themselves until sign-in without reintroducing that.
pages = {
    "Command Center": [
        st.Page("pages/command_center.py", title="Incidents", icon=":material/warning:", default=True),
    ],
    "Tools": [
        st.Page("pages/investigate.py", title="Investigate", icon=":material/search:"),
        st.Page("pages/network.py", title="Network", icon=":material/hub:"),
        st.Page("pages/health.py", title="Health", icon=":material/monitor_heart:"),
    ],
}
nav = st.navigation(pages, position="sidebar" if _is_authenticated else "hidden")


def _bind_enter_to_submit() -> None:
    # Belt-and-suspenders for Enter-to-submit: Streamlit's own form
    # handling normally does this, but it's shown to silently no-op
    # in at least one real browser/autofill combination (Enter does
    # nothing, no error, nothing in the console -- reported and
    # reproduced). st.markdown(unsafe_allow_html=True) never executes
    # injected <script> tags (WHATWG spec: scripts inserted via
    # innerHTML don't run); components.html renders in a real iframe
    # that does. window.parent.document reaches into the actual page
    # since this component iframe is same-origin.
    components.html(
        """
        <script>
        (function () {
            const doc = window.parent.document;
            function bind() {
                const inputs = doc.querySelectorAll('[data-testid="stTextInput"] input');
                const btn = doc.querySelector('[data-testid="stBaseButton-primaryFormSubmit"]');
                if (!btn || inputs.length === 0) { setTimeout(bind, 200); return; }
                inputs.forEach(function (input) {
                    if (input.dataset.tsocEnterBound) return;
                    input.dataset.tsocEnterBound = "1";
                    input.addEventListener('keydown', function (e) {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            btn.click();
                        }
                    });
                });
            }
            bind();
        })();
        </script>
        """,
        height=0,
    )


def _mfa_challenge_form(mid) -> None:
    """Second step of login for an admin with MFA enabled -- password
    already checked out (api/routes/auth.py's login() only returns
    mfa_required once it has), this just needs a current code from the
    authenticator app."""
    with mid:
        st.markdown(
            '<div class="tsoc-login-card">'
            f'<div class="tsoc-login-card__title">{svg("shield", 26)} T-SOC</div>'
            '<div class="tsoc-login-card__subtitle">Enter your authenticator code</div>'
            "</div>",
            unsafe_allow_html=True,
        )
        with st.form("mfa_form"):
            code = st.text_input("6-digit code", max_chars=6, autocomplete="one-time-code")
            submitted = st.form_submit_button("Verify", width="stretch", type="primary")
        _bind_enter_to_submit()
        if st.button("← Back to login", width="stretch"):
            st.session_state.pop("_pending_mfa_token", None)
            st.session_state.pop("_pending_mfa_email", None)
            st.rerun()

        if submitted:
            try:
                resp = requests.post(
                    f"{_API_URL}/auth/mfa/verify",
                    json={"mfa_token": st.session_state["_pending_mfa_token"], "code": code.strip()},
                    timeout=5,
                )
            except requests.RequestException:
                st.error("Could not reach the T-SOC API. Try again shortly.")
            else:
                if resp.status_code == 200:
                    st.session_state["access_token"] = resp.json()["access_token"]
                    st.session_state["analyst_name"] = st.session_state.pop("_pending_mfa_email", "")
                    st.session_state.pop("_pending_mfa_token", None)
                    st.rerun()
                else:
                    st.error("Incorrect or expired code.")


def _authenticated() -> bool:
    """Mandatory app-level login gate: a real per-employee account
    (api/routes/auth.py's /auth/login), not a single password shared by
    everyone -- the JWT it returns is what identifies both which tenant
    this session belongs to and who is acting, for every API call and
    every triage action this session makes from here on."""
    if _is_authenticated:
        return True

    _, mid, _ = st.columns([1, 1.2, 1])

    if st.session_state.get("_pending_mfa_token"):
        _mfa_challenge_form(mid)
        return False

    with mid:
        st.markdown(
            '<div class="tsoc-login-card">'
            f'<div class="tsoc-login-card__title">{svg("shield", 26)} T-SOC</div>'
            '<div class="tsoc-login-card__subtitle">Security Operations Center</div>'
            "</div>",
            unsafe_allow_html=True,
        )
        with st.form("login_form"):
            email = st.text_input("Email", autocomplete="username")
            # A correct, standard autocomplete hint (vs none/"off") makes
            # password managers more likely to fill this the same way a
            # real browser login form works -- via a proper input event
            # React's controlled component actually observes -- rather
            # than a raw value set that can desync from what Enter/submit
            # reads. Browsers largely ignore autocomplete="off" on
            # password fields anyway.
            entered = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", width="stretch", type="primary")
        _bind_enter_to_submit()

        if submitted:
            try:
                resp = requests.post(
                    f"{_API_URL}/auth/login",
                    json={"email": email.strip(), "password": entered},
                    timeout=5,
                )
            except requests.RequestException:
                st.error("Could not reach the T-SOC API. Try again shortly.")
            else:
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("mfa_required"):
                        st.session_state["_pending_mfa_token"] = body["mfa_token"]
                        st.session_state["_pending_mfa_email"] = email.strip()
                        st.rerun()
                    else:
                        st.session_state["access_token"] = body["access_token"]
                        st.session_state["analyst_name"] = email.strip()
                        st.rerun()
                elif resp.status_code == 429:
                    st.error("Too many failed attempts. Try again later.")
                else:
                    st.error("Incorrect email or password.")
    return False


if not _authenticated():
    st.stop()

# Runs once here for every page, since st.navigation always executes
# this entrypoint first regardless of which page is selected -- reads
# this session's own tenant via st.session_state["access_token"], not a
# process-wide poll shared across every tenant's employees.
status = session_data.status()

with st.sidebar:
    st.markdown(connection_pill(status["broker_healthy"]), unsafe_allow_html=True)
    # Read-only: this is a verified identity from login now, not a
    # free-text field anyone could edit to attribute their actions to
    # someone else's name.
    st.caption(f"Signed in as {st.session_state.get('analyst_name', '')}")
    if st.button("Log out", width="stretch"):
        try:
            requests.post(
                f"{_API_URL}/auth/logout",
                json={"token": st.session_state.get("access_token", "")},
                timeout=5,
            )
        except requests.RequestException:
            pass  # best-effort revocation; the session is being cleared either way
        st.session_state.pop("access_token", None)
        st.session_state.pop("analyst_name", None)
        st.rerun()
    st.caption("ENV: DEMO · DIODE: ONE-WAY")

nav.run()
