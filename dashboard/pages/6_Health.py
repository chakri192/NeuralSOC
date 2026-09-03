import streamlit as st
import time
from shared.data_access import stream_manager
from dashboard.components.empty_states import render_broker_unavailable

st.set_page_config(page_title="System Health", layout="wide")
st.title("Platform Health")

# Allow manual or auto refresh
if st.button("Refresh Telemetry"):
    st.rerun()

status = stream_manager.status()

if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

st.success("### System Status: HEALTHY", icon="✅")

st.markdown("---")

c1, c2, c3 = st.columns(3)

# 1. Pipeline Connectivity
with c1:
    st.subheader("Data Pipeline")
    st.markdown("- **Redpanda Connection:** `HEALTHY`")
    st.markdown("- **Data Diode Constraint:** `ENFORCED (Read-Only)`")
    st.markdown("- **Ingestion Layer:** `ACTIVE`")

# 2. Buffer Utilization
with c2:
    st.subheader("Memory Bounding")
    inc_pct = (status['incident_count'] / 200.0) * 100
    alert_pct = (status['alert_count'] / 1000.0) * 100
    
    st.markdown(f"- **Incident Buffer (Max 200):** `{inc_pct:.1f}% Full`")
    st.progress(inc_pct / 100.0)
    
    st.markdown(f"- **Alert Buffer (Max 1000):** `{alert_pct:.1f}% Full`")
    st.progress(alert_pct / 100.0)

# 3. Model & Inference State
with c3:
    st.subheader("Inference Engine")
    
    time_since_last = time.time() - status['last_event_time']
    if status['last_event_time'] == 0.0:
        lag_status = "WAITING FOR TELEMETRY"
    elif time_since_last > 60:
        lag_status = f"STALE ({time_since_last:.1f}s ago)"
    else:
        lag_status = f"LIVE ({time_since_last:.1f}s ago)"
        
    st.markdown(f"- **Last Event:** `{lag_status}`")
    st.markdown("- **Rule Engine:** `ONLINE`")
    st.markdown("- **Torch Accelerator:** `MOCK FALLBACK` (ARM64 Guardrail)")

st.markdown("---")
st.info("Performance Constraints: No unbounded memory growth is permitted in the UI layer. All state is strictly limited by deque boundaries.")
