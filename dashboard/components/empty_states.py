import streamlit as st

from dashboard.components.icons import svg

# icon="" previously passed to every call below -- Streamlit raises
# StreamlitAPIException for an empty-string icon (it must be a real emoji
# or None). Wired into all six dashboard pages, this meant the one
# "graceful degradation" component was itself 100% non-functional: a
# backend outage showed a raw uncaught exception instead of any of these
# messages.


def _render(icon_name: str, title: str, body: str) -> None:
    st.markdown(
        f"""
        <div class="tsoc-panel tsoc-empty">
            <div class="tsoc-empty__icon">{svg(icon_name, size=32, stroke_width=1.4)}</div>
            <div class="tsoc-empty__title">{title}</div>
            <div>{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_no_alerts():
    _render("check-circle", "No active incidents", "The sensor is receiving data and no correlated threats require attention.")


def render_broker_unavailable():
    _render(
        "alert-triangle",
        "Data pipeline unavailable",
        "The UI is showing the last known state. No new events can be confirmed. Check the Redpanda connection.",
    )


def render_no_telemetry(last_time_str="Unknown"):
    _render("alert-triangle", "No telemetry received", f"Last event: {last_time_str}. Check the Zeek sensor and ingestion process.")


def render_model_unavailable():
    _render("info", "ML detector unavailable", "Rule-based detections remain active. Model scores are not available.")
