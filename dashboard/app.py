import sys
import os
import secrets

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
import streamlit.components.v1 as components

from shared.auth import DEFAULT_DASHBOARD_USERNAME, resolve_dashboard_password
from shared.data_access import stream_manager
from dashboard.components.icons import svg
from dashboard.components.ui import inject_theme, connection_pill

st.set_page_config(
    page_title="T-SOC Operations Center",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon=":material/security:",
)

inject_theme()
_is_authenticated = bool(st.session_state.get("dashboard_authenticated"))

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


@st.cache_resource
def _resolve_dashboard_password() -> str:
    """Wraps resolve_dashboard_password() so its warning prints once per
    process, not once per rerun -- Streamlit re-executes this whole
    script on every interaction, so a bare module-level call would spam
    the log on every click."""
    return resolve_dashboard_password(warn=True)


_DASHBOARD_PASSWORD = _resolve_dashboard_password()

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


def _authenticated() -> bool:
    """Mandatory app-level login gate (see _DASHBOARD_PASSWORD above)."""
    if _is_authenticated:
        return True

    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.markdown(
            '<div class="tsoc-login-card">'
            f'<div class="tsoc-login-card__title">{svg("shield", 26)} T-SOC</div>'
            '<div class="tsoc-login-card__subtitle">Security Operations Center</div>'
            "</div>",
            unsafe_allow_html=True,
        )
        with st.form("login_form"):
            # No default/prefilled value: "user"/"user" is a convenience
            # fallback credential (see _DASHBOARD_PASSWORD above), not
            # something the login form itself should hint at to whoever
            # opens it.
            name = st.text_input("Your name", autocomplete="name")
            # A correct, standard autocomplete hint (vs none/"off") makes
            # password managers more likely to fill this the same way a
            # real browser login form works -- via a proper input event
            # React's controlled component actually observes -- rather
            # than a raw value set that can desync from what Enter/submit
            # reads. Browsers largely ignore autocomplete="off" on
            # password fields anyway.
            entered = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", width="stretch", type="primary")

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

        if submitted:
            if secrets.compare_digest(entered, _DASHBOARD_PASSWORD):
                st.session_state["dashboard_authenticated"] = True
                st.session_state["analyst_name"] = name.strip() or DEFAULT_DASHBOARD_USERNAME
                st.rerun()
            else:
                st.error("Incorrect password.")
    return False


if not _authenticated():
    st.stop()

# Idempotent (guarded by is_running) -- runs once here for every page,
# since st.navigation always executes this entrypoint first regardless
# of which page is selected.
stream_manager.start_listeners()
status = stream_manager.status()

with st.sidebar:
    st.markdown(connection_pill(status["broker_healthy"]), unsafe_allow_html=True)
    st.text_input("Analyst name", key="analyst_name")
    st.caption("ENV: DEMO · DIODE: ONE-WAY")

nav.run()
