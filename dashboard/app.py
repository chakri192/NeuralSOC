#!/usr/bin/env python3
"""
app.py
======
Refined Web Dashboard for Enterprise SOC Teams.
Focuses on clear typography, robust metrics, reliable time-series, and strict professional design.
"""

import streamlit as st
import pandas as pd
import json
import time
from datetime import datetime, timedelta
from collections import deque
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px

try:
    from kafka import KafkaConsumer
except ImportError:
    from kafka_python_ng import KafkaConsumer

# ==========================================
# Global Configuration
# ==========================================
st.set_page_config(
    page_title="SOC Unified Platform",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for a refined, modern "Datadog/Splunk" aesthetic
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');

    .stApp { background-color: #0B0E14; color: #94A3B8; font-family: 'Inter', sans-serif; }
    
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
    
    /* Elegant Metric Cards */
    div[data-testid="metric-container"] {
        background-color: #151923;
        border: 1px solid #1E293B;
        padding: 20px;
        border-radius: 6px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.4);
        transition: all 0.2s ease-in-out;
    }
    div[data-testid="metric-container"]:hover { border-color: #334155; }
    
    div[data-testid="metric-container"] label {
        color: #64748B !important;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #F8FAFC;
        font-size: 2.2rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    div[data-testid="stMetricDelta"] svg { fill: #34D399; }
    
    /* Header Bar */
    .dashboard-header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 10px 0 20px 0; border-bottom: 1px solid #1E293B; margin-bottom: 30px;
    }
    .header-title { font-size: 1.4rem; font-weight: 700; color: #F8FAFC; }
    .header-status { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; font-weight: 600; color: #34D399; }
    .pulse-dot {
        width: 8px; height: 8px; background-color: #34D399; border-radius: 50%;
        box-shadow: 0 0 8px #34D399; animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(52, 211, 153, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); }
    }
    
    /* Section Titles */
    .section-title {
        font-size: 1rem; font-weight: 600; color: #E2E8F0; margin-bottom: 15px; margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# Data State Management
# ==========================================
if "alerts" not in st.session_state:
    st.session_state.alerts = deque(maxlen=500) 
if "stats" not in st.session_state:
    st.session_state.stats = {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
if "start_time" not in st.session_state:
    st.session_state.start_time = time.time()
if "last_total" not in st.session_state:
    st.session_state.last_total = 0

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
        raw_msgs = st.session_state.consumer.poll(timeout_ms=100, max_records=100)
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

# Calculate dynamic deltas
delta_total = st.session_state.stats['total'] - st.session_state.last_total
st.session_state.last_total = st.session_state.stats['total']

# ==========================================
# UI Layout Render
# ==========================================

st.markdown("""
<div class="dashboard-header">
    <div class="header-title">Unified Threat Intelligence Platform</div>
    <div class="header-status"><div class="pulse-dot"></div> TELEMETRY ONLINE</div>
</div>
""", unsafe_allow_html=True)

# 1. Top Metrics Grid
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Total Ingested Flows", f"{st.session_state.stats['total']:,}", f"+{delta_total} (last tick)")
with m2:
    st.metric("Critical Anomalies", f"{st.session_state.stats['CRITICAL']:,}", delta=None)
with m3:
    st.metric("High Severity Alerts", f"{st.session_state.stats['HIGH']:,}", delta=None)
with m4:
    uptime_sec = int(time.time() - st.session_state.start_time)
    uptime_str = str(timedelta(seconds=uptime_sec))
    st.metric("System Uptime", uptime_str, delta=None)


if not st.session_state.alerts:
    st.info("System operational. Listening for network metadata on Kafka broker...")
else:
    # Build DataFrame
    df = pd.DataFrame(st.session_state.alerts)
    if 'timestamp' in df.columns:
        df['Time'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce').dt.strftime('%H:%M:%S')
    else:
        df['Time'] = 'N/A'
        
    df['Severity'] = df.get('severity', 'LOW').str.upper()
    df['Signature'] = df.get('threat_class', 'Unknown').str.replace('_', ' ').str.title()
    df['Source'] = df.get('src_ip', '').astype(str) + ":" + df.get('src_port', '').astype(str)
    df['Target'] = df.get('dst_ip', '').astype(str) + ":" + df.get('dst_port', '').astype(str)
    df['Confidence'] = df.get('confidence_score', 0.0) * 100

    # 2. Main Row (Alert Feed Table + Threat Distribution Donut)
    row1_col1, row1_col2 = st.columns([7, 3])
    
    with row1_col1:
        st.markdown('<div class="section-title">Live Alert Feed</div>', unsafe_allow_html=True)
        display_df = df[['Time', 'Severity', 'Signature', 'Source', 'Target', 'Confidence']].head(30)
        
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            height=320,
            column_config={
                "Severity": st.column_config.TextColumn("Sev"),
                "Confidence": st.column_config.ProgressColumn("Conf", format="%.0f%%", min_value=0, max_value=100),
            }
        )

    with row1_col2:
        st.markdown('<div class="section-title">Threat Signatures</div>', unsafe_allow_html=True)
        if len(df) > 0:
            sig_counts = df['Signature'].value_counts().reset_index()
            sig_counts.columns = ['Signature', 'Count']
            
            fig_donut = px.pie(
                sig_counts, values='Count', names='Signature', hole=0.7,
                color_discrete_sequence=px.colors.sequential.Tealgrn
            )
            fig_donut.update_layout(
                showlegend=False,
                margin=dict(l=0, r=0, t=10, b=10),
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                annotations=[dict(text=f"{len(sig_counts)}<br>Classes", x=0.5, y=0.5, font_size=14, font_color="#94A3B8", showarrow=False)],
                height=320
            )
            fig_donut.update_traces(textposition='inside', textinfo='percent+label', marker=dict(line=dict(color='#0B0E14', width=2)))
            st.plotly_chart(fig_donut, use_container_width=True, config={'displayModeBar': False})

    # 3. Bottom Row (Velocity Graph + Network Topology)
    row2_col1, row2_col2 = st.columns([6, 4])
    
    with row2_col1:
        st.markdown('<div class="section-title">Detection Velocity (Events per Second)</div>', unsafe_allow_html=True)
        if 'timestamp' in df.columns:
            velocity_df = df.copy()
            velocity_df['Sec'] = pd.to_datetime(velocity_df['timestamp'], unit='s', errors='coerce').dt.floor('S')
            v_counts = velocity_df.groupby('Sec').size().reset_index(name='Count')
            
            fig_line = px.bar(
                v_counts.tail(60), x='Sec', y='Count',
                color_discrete_sequence=['#3B82F6']
            )
            fig_line.update_layout(
                margin=dict(l=0, r=0, t=10, b=0),
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=False, title="", visible=False),
                yaxis=dict(showgrid=True, gridcolor='#1E293B', title="", side="right"),
                height=250, bargap=0.2
            )
            st.plotly_chart(fig_line, use_container_width=True, config={'displayModeBar': False})

    with row2_col2:
        st.markdown('<div class="section-title">Compromise Topology</div>', unsafe_allow_html=True)
        G = nx.DiGraph()
        
        # Build strict topological map of the last 30 alerts
        for _, row in df.head(30).iterrows():
            src = row.get('src_ip')
            dst = row.get('dst_ip')
            if pd.notna(src) and pd.notna(dst):
                G.add_edge(src, dst)
                
        if len(G.nodes) > 0:
            pos = nx.spring_layout(G, seed=42)
            edge_x, edge_y = [], []
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                
            edges_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color='#334155'), mode='lines', hoverinfo='none')
            
            node_x, node_y, node_text = [], [], []
            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(node)
                
            nodes_trace = go.Scatter(
                x=node_x, y=node_y, mode='markers',
                hovertext=node_text, hoverinfo='text',
                marker=dict(size=10, color='#F43F5E', line=dict(width=1, color='#0B0E14'))
            )
            
            fig_net = go.Figure(data=[edges_trace, nodes_trace])
            fig_net.update_layout(
                showlegend=False, margin=dict(l=0, r=0, t=0, b=0),
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=250
            )
            st.plotly_chart(fig_net, use_container_width=True, config={'displayModeBar': False})
        else:
            st.caption("Insufficient topology data.")

# Auto-refresh
time.sleep(1.0)
st.rerun()
