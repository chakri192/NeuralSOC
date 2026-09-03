import streamlit as st
import pandas as pd
import plotly.express as px
from shared.data_access import stream_manager
from dashboard.components.empty_states import render_broker_unavailable
from shared.formatters import categorize_evidence, format_timestamp

st.set_page_config(page_title="Investigate", layout="wide")
st.title("Deep Investigation")

status = stream_manager.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

st.markdown("Search across recent telemetry (IP, Domain, or ID) within the bounded 1000-event memory buffer.")

search_term = st.text_input("Entity Query:")
st.markdown("---")

if search_term:
    alerts = stream_manager.get_alerts()
    df = pd.DataFrame(alerts)
    
    if df.empty:
        st.warning("No telemetry available to search.")
    else:
        # Filter across multiple possible fields safely
        filtered = df[
            (df['source_ip'] == search_term) | 
            (df['destination_ip'] == search_term) | 
            (df['alert_id'] == search_term) |
            (df['flow_id'] == search_term)
        ]
        
        if filtered.empty:
            st.info(f"No evidence found for `{search_term}` in the active retention window.")
        else:
            c1, c2 = st.columns(2)
            c1.metric("Signals Found", len(filtered))
            c2.metric("First Seen in Window", format_timestamp(filtered.iloc[0]['timestamp']))
            
            st.subheader("Activity Timeline")
            # Volume trend
            filtered['time_group'] = pd.to_datetime(filtered['timestamp']).dt.floor('S')
            timeline_df = filtered.groupby('time_group').size().reset_index(name='count')
            
            fig = px.bar(
                timeline_df, 
                x='time_group', 
                y='count',
                labels={'time_group': 'Time', 'count': 'Event Count'},
                color_discrete_sequence=['#00bcd4']
            )
            fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=200)
            st.plotly_chart(fig, use_container_width=True)
            
            st.subheader("Raw Evidence Details")
            for idx, row in filtered.iterrows():
                with st.expander(f"{format_timestamp(row['timestamp'])} | {row['threat_class']} | {row['model_name']}"):
                    st.json(row.to_dict())
