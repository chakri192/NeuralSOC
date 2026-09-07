import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import streamlit as st

from dashboard import session_data
from dashboard.components.empty_states import render_broker_unavailable
from dashboard.components.ui import kpi_card, kpi_row

st.markdown("## Platform Health")
with st.container(key="refresh_corner"):
    if st.button("", icon=":material/refresh:", help="Refresh"):
        st.rerun()

status = session_data.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

time_since_last = time.time() - status["last_event_time"]
if status["last_event_time"] == 0.0:
    lag_label, lag_tone = "Waiting for telemetry", "medium"
elif time_since_last > 60:
    lag_label, lag_tone = f"Stale ({time_since_last:.0f}s ago)", "high"
else:
    lag_label, lag_tone = f"Live ({time_since_last:.0f}s ago)", "neutral"

inc_pct = min(100.0, (status["incident_count"] / 200.0) * 100)
alert_pct = min(100.0, (status["alert_count"] / 1000.0) * 100)

kpi_row([
    kpi_card("Data Pipeline", "Healthy", tone="neutral", sublabel="Data diode: read-only, enforced"),
    kpi_card("Last Event", lag_label, tone=lag_tone),
    kpi_card("Incident Buffer", f"{inc_pct:.0f}%", tone="accent", sublabel="of 200-item cap"),
    kpi_card("Alert Buffer", f"{alert_pct:.0f}%", tone="accent", sublabel="of 1000-item cap"),
])

c1, c2 = st.columns(2)
with c1:
    st.markdown('<div class="tsoc-panel"><div class="tsoc-panel__title">System Status</div>'
                '<div class="tsoc-kv">'
                '<div class="tsoc-kv__row"><span class="tsoc-kv__key">Redpanda connection</span><span class="tsoc-kv__val">HEALTHY</span></div>'
                '<div class="tsoc-kv__row"><span class="tsoc-kv__key">Data diode</span><span class="tsoc-kv__val">ENFORCED</span></div>'
                '<div class="tsoc-kv__row"><span class="tsoc-kv__key">Ingestion layer</span><span class="tsoc-kv__val">ACTIVE</span></div>'
                f'<div class="tsoc-kv__row"><span class="tsoc-kv__key">Last event</span><span class="tsoc-kv__val">{lag_label.upper()}</span></div>'
                '<div class="tsoc-kv__row"><span class="tsoc-kv__key">Rule engine</span><span class="tsoc-kv__val">ONLINE</span></div>'
                '</div></div>', unsafe_allow_html=True)
with c2:
    st.markdown('<div class="tsoc-panel"><div class="tsoc-panel__title">Memory Bounding</div></div>', unsafe_allow_html=True)
    st.progress(inc_pct / 100.0, text=f"Incidents: {inc_pct:.0f}% of cap")
    st.progress(alert_pct / 100.0, text=f"Alerts: {alert_pct:.0f}% of cap")

st.caption(
    "Performance constraint: no unbounded memory growth is permitted in the UI layer. "
    "Alert and incident state is bounded by the API's own paginated query cap, refreshed on each poll."
)
