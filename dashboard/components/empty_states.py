import streamlit as st

# icon="" previously passed to every call below -- Streamlit raises
# StreamlitAPIException for an empty-string icon (it must be a real emoji
# or None). Wired into all six dashboard pages, this meant the one
# "graceful degradation" component was itself 100% non-functional: a
# backend outage showed a raw uncaught exception instead of any of these
# messages.

def render_no_alerts():
    st.info("### No active incidents\nThe sensor is receiving data and no correlated threats require attention.")

def render_broker_unavailable():
    st.error("### Data pipeline unavailable\nThe UI is showing the last known state. No new events can be confirmed. Check Redpanda connection.")

def render_no_telemetry(last_time_str="Unknown"):
    st.warning(f"### No telemetry received\nLast event: {last_time_str}. Check the Zeek sensor and ingestion process.")

def render_model_unavailable():
    st.warning("### ML detector unavailable\nRule-based detections remain active. Model scores are not available.")
