#!/usr/bin/env python3
"""
app.py
======
Minimalist, Enterprise-Grade SOC Web Dashboard.
Focuses strictly on necessary telemetry and actionable intelligence.
"""

import streamlit as st
import pandas as pd
import json
import time
import altair as alt
from collections import deque
import networkx as nx
import plotly.graph_objects as go

try:
    from kafka import KafkaConsumer
except ImportError:
    from kafka_python_ng import KafkaConsumer

# ==========================================
# Page Configuration & CSS
# ==========================================
st.set_page_config(
    page_title="SOC Defense Control",
    layout="wide",
    page_icon="bar-chart",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    /* Ultra-clean minimalist theme */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
    }
    .metric-container {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .text-critical { color: #ef4444; }
    .text-high { color: #f97316; }
    .text-medium { color: #eab308; }
    .text-safe { color: #22c55e; }
    
    /* Hide unwanted Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ==========================================
# Data Management (Session State)
# ==========================================
if "alerts" not in st.session_state:
    st.session_state.alerts = deque(maxlen=50) # Keep only the last 50 for a clean view
if "stats" not in st.session_state:
    st.session_state.stats = {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
if "consumer" not in st.session_state:
    try:
        st.session_state.consumer = KafkaConsumer(
            "security_alerts",
            bootstrap_servers=["localhost:9092"],
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            consumer_timeout_ms=100
        )
    except Exception:
        st.session_state.consumer = None

# ==========================================
# Data Polling
# ==========================================
def poll_kafka():
    if not st.session_state.consumer:
        return
    try:
        raw_msgs = st.session_state.consumer.poll(timeout_ms=100, max_records=50)
        for tp, msgs in raw_msgs.items():
            for msg in msgs:
                alert = msg.value
                st.session_state.alerts.appendleft(alert)
                st.session_state.stats["total"] += 1
                sev = alert.get("severity", "LOW").upper()
                if sev in st.session_state.stats:
                    st.session_state.stats[sev] += 1
    except Exception:
        pass

poll_kafka()

# ==========================================
# UI Layout
# ==========================================
st.markdown("<h2 style='text-align: center; margin-bottom: 2rem; font-weight: 300;'>AI Cyber Threat Detection Enclave</h2>", unsafe_allow_html=True)

# 1. High-Level KPIs
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
        <div class="metric-container">
            <p class="metric-value">{st.session_state.stats['total']}</p>
            <p class="metric-label">Total Threats Evaluated</p>
        </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
        <div class="metric-container">
            <p class="metric-value text-critical">{st.session_state.stats['CRITICAL']}</p>
            <p class="metric-label">Critical Incidents</p>
        </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
        <div class="metric-container">
            <p class="metric-value text-high">{st.session_state.stats['HIGH']}</p>
            <p class="metric-label">High Severity</p>
        </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
        <div class="metric-container">
            <p class="metric-value text-medium">{st.session_state.stats['MEDIUM']}</p>
            <p class="metric-label">Medium Severity</p>
        </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# 2. Main Alert Feed (Clean Table)
if not st.session_state.alerts:
    st.info("No threats detected yet. Monitoring live traffic...")
else:
    # Convert deque to clean DataFrame
    df_alerts = pd.DataFrame(st.session_state.alerts)
    
    # Format time and IPs for clean display
    df_alerts['Time'] = pd.to_datetime(df_alerts['timestamp']).dt.strftime('%H:%M:%S')
    df_alerts['Source'] = df_alerts['src_ip'] + ":" + df_alerts['src_port'].astype(str)
    df_alerts['Destination'] = df_alerts['dst_ip'] + ":" + df_alerts['dst_port'].astype(str)
    
    # Extract just the main reason from evidence, ignore the rest of the JSON clutter
    df_alerts['AI Reason'] = df_alerts['evidence'].apply(lambda x: x.get('reason', 'Unknown Anomaly') if isinstance(x, dict) else 'Unknown Anomaly')
    
    # Select only necessary columns
    clean_df = df_alerts[['Time', 'severity', 'threat_class', 'Source', 'Destination', 'AI Reason']].copy()
    clean_df.columns = ['Time', 'Severity', 'Threat Type', 'Source', 'Destination', 'AI Context']
    
    st.markdown("### Live Threat Triage")
    st.dataframe(
        clean_df,
        use_container_width=True,
        hide_index=True,
        height=400
    )

# 3. Minimalist Network Graph
st.markdown("### Active Compromise Topology")
if len(st.session_state.alerts) > 0:
    G = nx.DiGraph()
    # Build graph from recent alerts
    for a in list(st.session_state.alerts)[:30]:
        src = a.get("src_ip", "Unknown")
        dst = a.get("dst_ip", "Unknown")
        sev = a.get("severity", "LOW")
        G.add_edge(src, dst, severity=sev)
        
    pos = nx.spring_layout(G, k=0.5, seed=42)
    
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
    edges_trace = go.Scatter(
        x=edge_x, y=edge_y, line=dict(width=1, color='#475569'),
        hoverinfo='none', mode='lines'
    )
    
    node_x, node_y, node_text = [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        
    nodes_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers+text',
        hoverinfo='text', text=node_text, textposition="top center",
        marker=dict(size=14, color='#38bdf8', lineWidth=2, line_color='white')
    )
    
    fig = go.Figure(data=[edges_trace, nodes_trace],
                 layout=go.Layout(
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=0,l=0,r=0,t=0),
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    height=300
                 ))
    
    st.plotly_chart(fig, use_container_width=True)
else:
    st.caption("Not enough data to map topology.")

# Auto-refresh loop
time.sleep(1.5)
st.rerun()
