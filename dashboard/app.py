#!/usr/bin/env python3
"""
app.py
======
Redesigned SOC Dashboard.
Uses native Streamlit components with advanced column configurations and stable network topologies for a highly professional, interactive experience.
"""

import streamlit as st
import pandas as pd
import json
import time
from collections import deque
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px

try:
    from kafka import KafkaConsumer
except ImportError:
    from kafka_python_ng import KafkaConsumer

# ==========================================
# Page Configuration & CSS
# ==========================================
st.set_page_config(
    page_title="Threat Detection Center",
    layout="wide",
    page_icon="🎯",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    /* Clean Dark Mode Reset */
    .stApp { background-color: #0f111a; }
    
    /* Remove padding */
    .block-container { padding-top: 1rem; padding-bottom: 1rem; max-width: 95%; }
    
    /* Hide Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Minimalist KPI Metrics */
    div[data-testid="metric-container"] {
        background-color: #1a1d2d;
        border: 1px solid #292d3e;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    div[data-testid="metric-container"] label {
        color: #82aaff !important;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        letter-spacing: 1px;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #ffffff;
        font-weight: 800;
    }
    
    /* Section Headers */
    .section-header {
        color: #82aaff;
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.2rem;
        font-weight: 700;
        margin-top: 20px;
        margin-bottom: 10px;
        border-bottom: 1px solid #292d3e;
        padding-bottom: 5px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# Data Management (Session State)
# ==========================================
if "alerts" not in st.session_state:
    st.session_state.alerts = deque(maxlen=200) # Keep history for timeline
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
# Dashboard Layout
# ==========================================

st.markdown("<h2 style='color: white; font-weight: 800;'>🎯 THREAT DETECTION CENTER</h2>", unsafe_allow_html=True)

# KPIs using native metrics but styled via CSS
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("TOTAL FLOWS ANALYZED", f"{st.session_state.stats['total']:,}")
with col2:
    st.metric("CRITICAL EXPLOITS", f"{st.session_state.stats['CRITICAL']:,}")
with col3:
    st.metric("HIGH SEVERITY", f"{st.session_state.stats['HIGH']:,}")
with col4:
    st.metric("MEDIUM ANOMALIES", f"{st.session_state.stats['MEDIUM']:,}")


if not st.session_state.alerts:
    st.info("Awaiting telemetry data from Kafka broker...")
else:
    # Convert deque to DataFrame
    df = pd.DataFrame(st.session_state.alerts)
    
    # Process columns safely
    if 'timestamp' in df.columns:
        df['Time'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce').dt.strftime('%H:%M:%S')
    else:
        df['Time'] = 'UNKNOWN'
        
    df['Severity'] = df.get('severity', 'LOW').str.upper()
    df['Threat'] = df.get('threat_class', 'Unknown Anomaly').str.replace('_', ' ')
    
    # Format IPs
    src_ip = df.get('src_ip', '')
    src_port = df.get('src_port', '')
    dst_ip = df.get('dst_ip', '')
    dst_port = df.get('dst_port', '')
    df['Source'] = src_ip.astype(str) + ":" + src_port.astype(str)
    df['Target'] = dst_ip.astype(str) + ":" + dst_port.astype(str)
    
    # Confidence 
    df['Confidence'] = df.get('confidence_score', 0.0) * 100

    # Layout: Top Row is Table, Bottom Row is Graphs
    st.markdown('<div class="section-header">LIVE INTRUSION FEED</div>', unsafe_allow_html=True)
    
    # Native interactive dataframe with column config (highly professional)
    display_df = df[['Time', 'Severity', 'Threat', 'Source', 'Target', 'Confidence']].head(30)
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=350,
        column_config={
            "Time": st.column_config.TextColumn("Timestamp", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Threat": st.column_config.TextColumn("Signature", width="medium"),
            "Source": st.column_config.TextColumn("Attacker IP", width="medium"),
            "Target": st.column_config.TextColumn("Target IP", width="medium"),
            "Confidence": st.column_config.ProgressColumn(
                "AI Confidence",
                help="Neural Network Confidence Score",
                format="%.0f%%",
                min_value=0,
                max_value=100,
            ),
        }
    )

    col_graph1, col_graph2 = st.columns(2)
    
    with col_graph1:
        st.markdown('<div class="section-header">THREAT VELOCITY (EVENTS/SEC)</div>', unsafe_allow_html=True)
        # Create a timeline chart
        if 'timestamp' in df.columns:
            # Group by second
            timeline_df = df.copy()
            timeline_df['Second'] = pd.to_datetime(timeline_df['timestamp'], unit='s', errors='coerce').dt.floor('S')
            counts = timeline_df.groupby('Second').size().reset_index(name='Count')
            
            fig_area = px.area(
                counts.tail(30), 
                x='Second', 
                y='Count',
                color_discrete_sequence=['#ef5350']
            )
            fig_area.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(showgrid=False, title=""),
                yaxis=dict(showgrid=True, gridcolor='#292d3e', title="Alerts"),
                height=300
            )
            st.plotly_chart(fig_area, use_container_width=True, config={'displayModeBar': False})

    with col_graph2:
        st.markdown('<div class="section-header">ACTIVE COMPROMISE TOPOLOGY</div>', unsafe_allow_html=True)
        # Real NetworkX Graph (Not random)
        G = nx.DiGraph()
        for _, row in df.head(25).iterrows():
            G.add_edge(row.get('src_ip', 'Unknown'), row.get('dst_ip', 'Unknown'), sev=row['Severity'])
            
        pos = nx.spring_layout(G, k=0.7, seed=42)
        
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
        edges_trace = go.Scatter(
            x=edge_x, y=edge_y, line=dict(width=1, color='#4b5563'),
            hoverinfo='none', mode='lines'
        )
        
        node_x, node_y, node_text, node_color = [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            node_color.append('#82aaff')
            
        nodes_trace = go.Scatter(
            x=node_x, y=node_y, mode='markers+text',
            hoverinfo='text', text=node_text, textposition="bottom center",
            textfont=dict(color="#94a3b8", size=10),
            marker=dict(size=14, color=node_color, line=dict(color='#ffffff', width=1))
        )
        
        fig_net = go.Figure(data=[edges_trace, nodes_trace])
        fig_net.update_layout(
            showlegend=False,
            margin=dict(l=0, r=0, t=10, b=0),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=300
        )
        st.plotly_chart(fig_net, use_container_width=True, config={'displayModeBar': False})

# Auto-refresh loop
time.sleep(1.0)
st.rerun()
