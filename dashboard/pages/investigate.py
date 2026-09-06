import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.components.empty_states import render_broker_unavailable
from dashboard.components.ui import relative_time, render_evidence_columns, severity_badge
from dashboard.theme import plotly_template
from shared.data_access import stream_manager
from shared.formatters import format_timestamp

st.markdown("## Investigate")
st.caption("Search recent telemetry (IP, domain, alert, or flow ID) within the bounded 1000-event memory buffer.")

status = stream_manager.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

search_term = st.text_input("Entity query", placeholder="e.g. 10.0.0.5, evil.example.com, ALERT-...")

if not search_term:
    st.info("Enter an IP, domain, alert ID, or flow ID above to search recent telemetry.")
    st.stop()

alerts = stream_manager.get_alerts()
df = pd.DataFrame(alerts)

if df.empty:
    st.warning("No telemetry available to search.")
    st.stop()

filtered = df[
    (df["source_ip"] == search_term)
    | (df["destination_ip"] == search_term)
    | (df["alert_id"] == search_term)
    | (df["flow_id"] == search_term)
]

if filtered.empty:
    st.info(f"No evidence found for `{search_term}` in the active retention window.")
    st.stop()

c1, c2 = st.columns(2)
c1.metric("Signals Found", len(filtered))
c2.metric("First Seen in Window", relative_time(filtered.iloc[0]["timestamp"]), help=format_timestamp(filtered.iloc[0]["timestamp"]))

# ---------- Cross-link to Command Center: this search may already be a live incident ----------

incidents_by_id = {i["incident_id"]: i for i in stream_manager.get_incidents()}
related_source_ips = [ip for ip in filtered["source_ip"].dropna().unique() if ip]
related_incidents = [
    incidents_by_id[f"INC-{ip.replace('.', '-')}"]
    for ip in related_source_ips
    if f"INC-{ip.replace('.', '-')}" in incidents_by_id
]

if related_incidents:
    st.markdown('<div class="tsoc-panel__title">Related Incidents</div>', unsafe_allow_html=True)
    for inc in related_incidents:
        row_l, row_r = st.columns([4, 1])
        with row_l:
            threat = inc["threat_classes"][0] if inc["threat_classes"] else "Unclassified"
            st.markdown(
                f'{severity_badge(inc["severity"])} <span class="tsoc-mono">{inc["incident_id"]}</span> · {threat}',
                unsafe_allow_html=True,
            )
        with row_r:
            if st.button("View →", key=f"view_{inc['incident_id']}", width="stretch"):
                st.session_state["incident_search"] = inc["incident_id"]
                st.switch_page("pages/command_center.py")

st.markdown('<div class="tsoc-panel__title">Activity Timeline</div>', unsafe_allow_html=True)
filtered = filtered.copy()
filtered["time_group"] = pd.to_datetime(filtered["timestamp"]).dt.floor("s")
timeline_df = filtered.groupby("time_group").size().reset_index(name="count")

fig = px.bar(timeline_df, x="time_group", y="count", labels={"time_group": "Time", "count": "Event Count"})
fig.update_traces(marker_color=plotly_template()["colorway"][-1])
fig.update_layout(**{**plotly_template(), "height": 220})
st.plotly_chart(fig)

st.markdown('<div class="tsoc-panel__title">Evidence Details</div>', unsafe_allow_html=True)
for _idx, row in filtered.iterrows():
    model_name = row.get("model_name") or "rule-based"
    with st.expander(f"{format_timestamp(row['timestamp'])} · {row['threat_class']} · {model_name}"):
        header_l, header_r = st.columns([3, 1])
        with header_l:
            st.markdown(
                f'{severity_badge(row.get("severity"))} '
                f'<span class="tsoc-mono">{row.get("source_ip", "?")} → {row.get("destination_ip", "?")}</span>',
                unsafe_allow_html=True,
            )
        with header_r:
            confidence = row.get("confidence_score")
            if confidence is not None:
                st.caption(f"Confidence: {confidence:.2f}")
        if row.get("mitre_tactic") or row.get("mitre_technique"):
            st.caption(f"MITRE: {row.get('mitre_tactic', '—')} ({row.get('mitre_technique', '—')})")
        render_evidence_columns(row.get("evidence", {}))
