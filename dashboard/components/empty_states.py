import streamlit as st

def render_no_alerts():
    st.info("### No active incidents\nThe sensor is receiving data and no correlated threats require attention.", icon="✅")

def render_broker_unavailable():
    st.error("### Data pipeline unavailable\nThe UI is showing the last known state. No new events can be confirmed. Check Redpanda connection.", icon="🚨")

def render_no_telemetry(last_time_str="Unknown"):
    st.warning(f"### No telemetry received\nLast event: {last_time_str}. Check the Zeek sensor and ingestion process.", icon="⚠️")

def render_model_unavailable():
    st.warning("### ML detector unavailable\nRule-based detections remain active. Model scores are not available.", icon="⚠️")
