import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import streamlit as st
import pandas as pd
import plotly.express as px
from shared.data_access import stream_manager
from dashboard.components.empty_states import render_no_alerts, render_broker_unavailable
from shared.formatters import format_timestamp

st.set_page_config(page_title="Overview", layout="wide")

def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "..", "styles", "app.css")
    if os.path.exists(css_path):
        with open(css_path, "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()
# Idempotent (guarded by is_running) -- needed here too, not just app.py,
# since Streamlit only executes the page matching the current URL. An
# analyst who bookmarks/deep-links this page directly would otherwise
# never start the poller, and broker_healthy would stay False forever.
stream_manager.start_listeners()
status = stream_manager.status()

col1, col2 = st.columns([9, 1])
with col1:
    st.markdown("##  Operations Overview")
with col2:
    if st.button("Refresh ↻"):
        st.rerun()

if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

incidents = stream_manager.get_incidents()
if not incidents:
    render_no_alerts()
    st.stop()

df = pd.DataFrame(incidents)

# Top Section KPIs - Rendered inside the custom styled cards from app.css
c1, c2, c3, c4 = st.columns(4)
c1.metric("Critical Incidents", len(df[df['severity'] == 'critical']))
c2.metric("High Incidents", len(df[df['severity'] == 'high']))
c3.metric("Total Active Incidents", len(df))
c4.metric("Avg Risk Score", f"{df['risk_score'].mean():.1f}")

st.markdown("<br>", unsafe_allow_html=True)

# Visualizations
c_left, c_right = st.columns(2)
with c_left:
    st.markdown("#### Top Attacker Origins")
    exploded = df.explode('affected_entities')
    top_ips = exploded['affected_entities'].value_counts().reset_index()
    top_ips.columns = ['IP Address', 'Incident Count']
    
    fig_bar = px.bar(
        top_ips.head(10), 
        x='Incident Count', 
        y='IP Address', 
        orientation='h',
        color_discrete_sequence=['#f7768e'] # Tokyo Night red
    )
    fig_bar.update_layout(
        yaxis={'categoryorder':'total ascending'}, 
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#c0caf5')
    )
    st.plotly_chart(fig_bar, use_container_width=True)

with c_right:
    st.markdown("#### Severity Distribution")
    fig_pie = px.pie(
        df, 
        names='severity', 
        color='severity', 
        color_discrete_map={'critical':'#f7768e', 'high':'#ff9e64', 'medium':'#e0af68', 'low':'#7dcfff'},
        hole=0.6
    )
    fig_pie.update_layout(
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#c0caf5')
    )
    st.plotly_chart(fig_pie, use_container_width=True)

st.markdown("---")
st.markdown("#### Incident Queue")

display_df = df[['created_timestamp', 'incident_id', 'severity', 'risk_score', 'threat_classes', 'affected_entities']].copy()
display_df['created_timestamp'] = display_df['created_timestamp'].apply(format_timestamp)
display_df['threat_classes'] = display_df['threat_classes'].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
display_df['affected_entities'] = display_df['affected_entities'].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
display_df = display_df.sort_values(by=['risk_score', 'created_timestamp'], ascending=[False, False])

st.dataframe(
    display_df, 
    use_container_width=True, 
    hide_index=True,
    height=400,
    column_config={
        "created_timestamp": st.column_config.DatetimeColumn("First Seen", format="YYYY-MM-DD HH:mm:ss"),
        "incident_id": st.column_config.TextColumn("Incident ID"),
        "severity": st.column_config.TextColumn("Severity"),
        "risk_score": st.column_config.ProgressColumn("Risk Score", format="%f", min_value=0, max_value=100),
        "threat_classes": st.column_config.TextColumn("Threat Classification"),
        "affected_entities": st.column_config.TextColumn("Target Entities")
    }
)
