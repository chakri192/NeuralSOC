#!/usr/bin/env python3
"""
app.py
======
Enterprise-Grade Cyber Security Operations Center (SOC) Dashboard.
Completely overrides Streamlit's default styles to mimic a high-end SIEM (like Splunk or CrowdStrike).
"""

import streamlit as st
import json
import time
from collections import deque
import plotly.graph_objects as go
import pandas as pd

try:
    from kafka import KafkaConsumer
except ImportError:
    from kafka_python_ng import KafkaConsumer

# ==========================================
# Page Configuration & Heavy CSS
# ==========================================
st.set_page_config(
    page_title="AI Threat Intelligence",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="collapsed"
)

# Completely override Streamlit's amateur styling with Enterprise CSS
st.markdown("""
<style>
    /* Reset and Layout */
    .stApp {
        background-color: #0b1120;
        color: #e2e8f0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Hide Streamlit Chrome */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Top Bar */
    .top-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 0 30px 0;
        border-bottom: 1px solid #1e293b;
        margin-bottom: 30px;
    }
    .top-bar-title {
        font-size: 1.5rem;
        font-weight: 700;
        letter-spacing: 1px;
        color: #f8fafc;
        display: flex;
        align-items: center;
        gap: 15px;
    }
    .live-indicator {
        display: inline-block;
        width: 10px; height: 10px;
        background-color: #22c55e;
        border-radius: 50%;
        box-shadow: 0 0 10px #22c55e;
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); }
        70% { box-shadow: 0 0 0 10px rgba(34, 197, 94, 0); }
        100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
    }

    /* KPI Cards Grid */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 20px;
        margin-bottom: 30px;
    }
    .kpi-card {
        background: linear-gradient(145deg, #1e293b, #0f172a);
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 24px;
        position: relative;
        overflow: hidden;
    }
    .kpi-card::before {
        content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    }
    .kpi-crit::before { background: #ef4444; box-shadow: 0 0 15px #ef4444; }
    .kpi-high::before { background: #f97316; box-shadow: 0 0 15px #f97316; }
    .kpi-med::before { background: #eab308; box-shadow: 0 0 15px #eab308; }
    .kpi-total::before { background: #3b82f6; box-shadow: 0 0 15px #3b82f6; }
    
    .kpi-value { 
        font-size: 2.5rem; font-weight: 800; margin: 0 0 5px 0; 
        font-family: 'JetBrains Mono', 'Courier New', monospace; 
        color: #f8fafc;
    }
    .kpi-label { 
        font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; 
        letter-spacing: 1px; font-weight: 600; margin: 0;
    }

    /* Custom SIEM Data Table */
    .siem-table-container {
        max-height: 450px;
        overflow-y: auto;
        border: 1px solid #334155;
        border-radius: 8px;
        background: #0f172a;
        margin-bottom: 30px;
    }
    .siem-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'JetBrains Mono', 'Courier New', monospace;
        font-size: 0.85rem;
    }
    .siem-table th {
        background: #1e293b;
        color: #cbd5e1;
        font-weight: 600;
        text-align: left;
        padding: 14px 20px;
        position: sticky;
        top: 0;
        border-bottom: 2px solid #334155;
        z-index: 10;
        letter-spacing: 0.5px;
    }
    .siem-table td {
        padding: 14px 20px;
        border-bottom: 1px solid #1e293b;
        color: #94a3b8;
    }
    .siem-table tr:hover { background: #1e293b; }
    .siem-table .highlight { color: #f8fafc; font-weight: 500; }
    
    .badge {
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        display: inline-block;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.5); }
    .badge-medium { background: rgba(234, 179, 8, 0.15); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.5); }
    .badge-low { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.5); }
    
    /* Panel Titles */
    .panel-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #f8fafc;
        margin-bottom: 15px;
        letter-spacing: 0.5px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# Data Management (Session State)
# ==========================================
if "alerts" not in st.session_state:
    st.session_state.alerts = deque(maxlen=50) # Keep only the last 50 for the table
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
# UI Layout Rendering
# ==========================================
# Top Header
st.markdown("""
<div class="top-bar">
    <div class="top-bar-title">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        AI THREAT INTELLIGENCE PLATFORM
    </div>
    <div style="color: #94a3b8; font-size: 0.9rem; font-weight: 600; display: flex; align-items: center; gap: 8px;">
        <span class="live-indicator"></span> LIVE TELEMETRY
    </div>
</div>
""", unsafe_allow_html=True)

# KPIs
st.markdown(f"""
<div class="kpi-grid">
    <div class="kpi-card kpi-total">
        <p class="kpi-value">{st.session_state.stats['total']:,}</p>
        <p class="kpi-label">Flows Evaluated</p>
    </div>
    <div class="kpi-card kpi-crit">
        <p class="kpi-value" style="color: #ef4444;">{st.session_state.stats['CRITICAL']:,}</p>
        <p class="kpi-label">Critical Exploits</p>
    </div>
    <div class="kpi-card kpi-high">
        <p class="kpi-value" style="color: #f97316;">{st.session_state.stats['HIGH']:,}</p>
        <p class="kpi-label">High Severity</p>
    </div>
    <div class="kpi-card kpi-med">
        <p class="kpi-value" style="color: #eab308;">{st.session_state.stats['MEDIUM']:,}</p>
        <p class="kpi-label">Medium Anomalies</p>
    </div>
</div>
""", unsafe_allow_html=True)

# Main Dashboard Grid (2 columns: Table taking 2/3, Graph taking 1/3)
col_feed, col_graph = st.columns([2, 1])

with col_feed:
    st.markdown('<div class="panel-title">Real-Time Intrusion Feed</div>', unsafe_allow_html=True)
    
    if not st.session_state.alerts:
        st.markdown("""
        <div class="siem-table-container" style="display: flex; align-items: center; justify-content: center; min-height: 400px; color: #64748b;">
            Awaiting network telemetry...
        </div>
        """, unsafe_allow_html=True)
    else:
        # Build HTML Table manually for pixel-perfect SIEM styling
        table_html = """
        <div class="siem-table-container">
            <table class="siem-table">
                <thead>
                    <tr>
                        <th>TIMESTAMP</th>
                        <th>SEVERITY</th>
                        <th>THREAT SIGNATURE</th>
                        <th>SOURCE</th>
                        <th>TARGET</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for a in list(st.session_state.alerts)[:35]:
            ts = pd.to_datetime(a.get('timestamp')).strftime('%H:%M:%S.%f')[:-3] if a.get('timestamp') else 'UNKNOWN'
            sev = a.get('severity', 'LOW').upper()
            badge_class = f"badge-{sev.lower()}"
            threat = a.get('threat_class', 'Unknown Anomaly').replace('_', ' ')
            src = f"{a.get('src_ip', '')}:{a.get('src_port', '')}"
            dst = f"{a.get('dst_ip', '')}:{a.get('dst_port', '')}"
            
            table_html += f"""
            <tr>
                <td>{ts}</td>
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td class="highlight">{threat}</td>
                <td>{src}</td>
                <td>{dst}</td>
            </tr>
            """
        table_html += "</tbody></table></div>"
        st.markdown(table_html, unsafe_allow_html=True)

with col_graph:
    st.markdown('<div class="panel-title">Active Kill-Chain Topology</div>', unsafe_allow_html=True)
    
    # Minimalist Dark Plotly Graph
    G = go.Figure()
    
    if len(st.session_state.alerts) > 0:
        edges_x, edges_y = [], []
        nodes_x, nodes_y, nodes_text = [], [], []
        
        # Simple simulated ring layout for visual flair
        import math
        import random
        alerts = list(st.session_state.alerts)[:15]
        
        # Add center node (Firewall / Diode)
        nodes_x.append(0)
        nodes_y.append(0)
        nodes_text.append("DATA DIODE")
        
        for i, a in enumerate(alerts):
            angle = (i / len(alerts)) * 2 * math.pi
            r = random.uniform(0.7, 1.0)
            nx, ny = r * math.cos(angle), r * math.sin(angle)
            
            nodes_x.append(nx)
            nodes_y.append(ny)
            
            src = a.get("src_ip", "")
            nodes_text.append(f"{src}")
            
            edges_x.extend([0, nx, None])
            edges_y.extend([0, ny, None])
            
        G.add_trace(go.Scatter(x=edges_x, y=edges_y, mode='lines', line=dict(color='#334155', width=1), hoverinfo='none'))
        G.add_trace(go.Scatter(x=nodes_x, y=nodes_y, mode='markers+text', 
                               text=nodes_text, textposition="top center",
                               textfont=dict(color="#94a3b8", size=9, family="JetBrains Mono"),
                               marker=dict(size=[20] + [10]*len(alerts), 
                                           color=['#3b82f6'] + ['#ef4444' if a.get('severity')=='CRITICAL' else '#f97316' for a in alerts],
                                           line=dict(color='#0f172a', width=2)),
                               hoverinfo='text'))
                               
    G.update_layout(
        showlegend=False,
        margin=dict(l=0, r=0, t=0, b=0),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=450
    )
    
    st.plotly_chart(G, use_container_width=True, config={'displayModeBar': False})

# Auto-refresh loop
time.sleep(1.0)
st.rerun()
