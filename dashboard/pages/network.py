import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.components.empty_states import render_broker_unavailable, render_no_alerts
from dashboard.components.ui import relative_time
from shared.data_access import stream_manager

_NEW_PAIR_WINDOW_MINUTES = 10

st.markdown("## Network")
st.caption("Top communicating pairs observed in the active telemetry window.")

status = stream_manager.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

alerts = stream_manager.get_alerts()
if not alerts:
    render_no_alerts()
    st.stop()

df = pd.DataFrame(alerts)

f1, f2 = st.columns(2)
with f1:
    min_confidence = st.slider("Min confidence score", 0.0, 1.0, 0.5)
with f2:
    max_rows = st.slider("Max pairs shown", 10, 100, 25)

filtered_df = df[df["confidence_score"] >= min_confidence]
if filtered_df.empty:
    st.info("No connections meet the current filter criteria.")
    st.stop()

relationships = filtered_df.groupby(["source_ip", "destination_ip"]).agg(
    weight=("source_ip", "size"),
    first_seen=("timestamp", "min"),
).reset_index()
relationships = relationships.sort_values(by="weight", ascending=False).head(max_rows)

# "New" here means "first appeared recently within this retained window"
# -- not "never seen before ever". The buffer itself is a bounded, rolling
# 1000-event window (see shared/data_access.py), not a long-term store,
# so genuine first-ever-seen tracking would need real persistence this
# page doesn't have. Still a real, useful signal: distinguishes a pair
# that's been talking the whole window from one that just started.
now = pd.Timestamp.now(tz="UTC")
first_seen_dt = pd.to_datetime(relationships["first_seen"], utc=True)
is_new = (now - first_seen_dt) <= pd.Timedelta(minutes=_NEW_PAIR_WINDOW_MINUTES)

display_df = pd.DataFrame({
    "Source": relationships["source_ip"],
    "Destination": relationships["destination_ip"],
    "Events": relationships["weight"],
    "First Seen": relationships["first_seen"].apply(relative_time),
    "Status": is_new.map({True: "NEW", False: ""}),
})

st.markdown('<div class="tsoc-panel__title">Top Talkers</div>', unsafe_allow_html=True)
st.caption(f"NEW marks a pair whose first appearance in this window was within the last {_NEW_PAIR_WINDOW_MINUTES} minutes.")
st.dataframe(
    display_df.style.map(lambda v: "color:#3b82f6; font-weight:700;" if v == "NEW" else "", subset=["Status"]),
    hide_index=True,
    column_config={"Events": st.column_config.ProgressColumn("Events", format="%d", min_value=0, max_value=int(relationships["weight"].max()))},
)

with st.expander("Show relationship diagram (Sankey) — a one-off deep-dive view, not a daily-use screen"):
    all_nodes = list(pd.unique(relationships[["source_ip", "destination_ip"]].values.ravel("K")))
    node_mapping = {node: i for i, node in enumerate(all_nodes)}
    relationships["source_idx"] = relationships["source_ip"].map(node_mapping)
    relationships["dest_idx"] = relationships["destination_ip"].map(node_mapping)

    node_color = "#3b82f6"
    # Plotly's color validator rejects 8-digit RGBA hex (e.g. "#f5a52466")
    # -- rgba(...) is the actual accepted translucent-color syntax.
    link_color = "rgba(245, 165, 36, 0.4)"

    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=15, thickness=18, line=dict(width=0), label=all_nodes, color=node_color),
        link=dict(source=relationships["source_idx"], target=relationships["dest_idx"], value=relationships["weight"], color=link_color),
    )])
    fig.update_layout(
        height=520,
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#eeeeee",
    )
    st.plotly_chart(fig)
