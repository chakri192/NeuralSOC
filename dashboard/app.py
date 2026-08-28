#!/usr/bin/env python3
"""
app.py
======
Enterprise-Grade SOC Dashboard.
Completely redesigned for maximum legibility, high-contrast data visualization,
and professional SIEM aesthetics (replacing messy network graphs with clean metrics).
"""

import streamlit as st
import pandas as pd
import json
import time
from datetime import datetime, timedelta
from collections import deque
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

# High-contrast CSS for Enterprise SIEM
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;600&display=swap');

    .stApp { background-color: #0d1117; color: #c9d1d9; font-family: 'Inter', sans-serif; }
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
    
    /* Elegant Metric Cards */
    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 24px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    div[data-testid="metric-container"] label {
        color: #8b949e !important;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #ffffff;
        font-size: 2.4rem;
        font-weight: 700;
        font-family: 'Fira Code', monospace;
    }
    
    /* Header Bar */
    .dashboard-header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 15px 0 25px 0; border-bottom: 1px solid #30363d; margin-bottom: 30px;
    }
    .header-title { font-size: 1.5rem; font-weight: 700; color: #ffffff; letter-spacing: 0.5px; }
    .header-status { display: flex; align-items: center; gap: 10px; font-size: 0.9rem; font-weight: 600; color: #3fb950; }
    .pulse-dot {
        width: 10px; height: 10px; background-color: #3fb950; border-radius: 50%;
        box-shadow: 0 0 10px #3fb950; animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(63, 185, 80, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(63, 185, 80, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(63, 185, 80, 0); }
    }
    
    /* Section Titles */
    .section-title {
        font-size: 1.1rem; font-weight: 600; color: #ffffff; margin-bottom: 20px; margin-top: 15px; border-left: 4px solid #58a6ff; padding-left: 10px;
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

delta_total = st.session_state.stats['total'] - st.session_state.last_total
st.session_state.last_total = st.session_state.stats['total']

# ==========================================
# UI Layout Render
# ==========================================

st.markdown("""
<div class="dashboard-header">
    <div class="header-title">Enterprise Threat Intelligence</div>
    <div class="header-status"><div class="pulse-dot"></div> SECURE PIPELINE ACTIVE</div>
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
    st.info("System operational. Awaiting network telemetry...")
else:
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

    # Professional Color Palette
    CHART_COLORS = ['#ff7b72', '#ffa657', '#3fb950', '#a5d6ff', '#d2a8ff', '#79c0ff']

    # 2. Top Row: Threat Distribution & Target Origins
    row1_col1, row1_col2 = st.columns([1, 1])
    
    with row1_col1:
        st.markdown('<div class="section-title">Active Threat Signatures</div>', unsafe_allow_html=True)
        sig_counts = df['Signature'].value_counts().reset_index()
        sig_counts.columns = ['Signature', 'Count']
        
        # High-contrast, highly legible Donut Chart
        fig_donut = go.Figure(data=[go.Pie(
            labels=sig_counts['Signature'], 
            values=sig_counts['Count'], 
            hole=0.6,
            marker=dict(colors=CHART_COLORS, line=dict(color='#0d1117', width=2)),
            textposition='outside',
            textinfo='label+percent',
            textfont=dict(color='#c9d1d9', size=12, family="Inter")
        )])
        fig_donut.update_layout(
            showlegend=False,
            margin=dict(l=20, r=20, t=20, b=20),
            plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
            height=300
        )
        st.plotly_chart(fig_donut, use_container_width=True, config={'displayModeBar': False})

    with row1_col2:
        st.markdown('<div class="section-title">Top Attacker Origins (Source IPs)</div>', unsafe_allow_html=True)
        # Replaced the messy network graph with a professional Top Talkers Bar Chart
        top_ips = df['src_ip'].value_counts().head(5).reset_index()
        top_ips.columns = ['Source IP', 'Alert Count']
        top_ips = top_ips.sort_values('Alert Count', ascending=True) # For horizontal bar chart
        
        fig_bar = go.Figure(go.Bar(
            x=top_ips['Alert Count'],
            y=top_ips['Source IP'],
            orientation='h',
            marker=dict(color='#ff7b72', line=dict(color='#0d1117', width=1)),
            text=top_ips['Alert Count'],
            textposition='outside',
            textfont=dict(color='#c9d1d9', family="Fira Code")
        ))
        fig_bar.update_layout(
            margin=dict(l=10, r=30, t=10, b=10),
            plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=True, gridcolor='#30363d', title=dict(text="Alert Volume", font=dict(color="#8b949e")), tickfont=dict(color="#8b949e")),
            yaxis=dict(showgrid=False, tickfont=dict(color="#c9d1d9", family="Fira Code", size=12)),
            height=300
        )
        st.plotly_chart(fig_bar, use_container_width=True, config={'displayModeBar': False})

    # 3. Middle Row: Detection Velocity Line Chart
    st.markdown('<div class="section-title">Detection Velocity (Events per Second)</div>', unsafe_allow_html=True)
    if 'timestamp' in df.columns:
        velocity_df = df.copy()
        velocity_df['Sec'] = pd.to_datetime(velocity_df['timestamp'], unit='s', errors='coerce').dt.floor('S')
        v_counts = velocity_df.groupby('Sec').size().reset_index(name='Count')
        
        # High visibility Area Chart
        fig_line = go.Figure(go.Scatter(
            x=v_counts['Sec'].tail(60), 
            y=v_counts['Count'].tail(60),
            fill='tozeroy',
            mode='lines+markers',
            line=dict(color='#58a6ff', width=3),
            marker=dict(size=6, color='#58a6ff', symbol='circle'),
            fillcolor='rgba(88, 166, 255, 0.15)'
        ))
        fig_line.update_layout(
            margin=dict(l=0, r=0, t=10, b=10),
            plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=True, gridcolor='#30363d', tickfont=dict(color="#8b949e")),
            yaxis=dict(showgrid=True, gridcolor='#30363d', tickfont=dict(color="#8b949e")),
            height=220
        )
        st.plotly_chart(fig_line, use_container_width=True, config={'displayModeBar': False})

    # 4. Bottom Row: Data Table
    st.markdown('<div class="section-title">Real-Time Intrusion Log</div>', unsafe_allow_html=True)
    display_df = df[['Time', 'Severity', 'Signature', 'Source', 'Target', 'Confidence']].head(50)
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=400,
        column_config={
            "Time": st.column_config.TextColumn("Time", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Signature": st.column_config.TextColumn("Threat Signature", width="medium"),
            "Confidence": st.column_config.ProgressColumn("AI Confidence", format="%.0f%%", min_value=0, max_value=100),
        }
    )

# Auto-refresh
time.sleep(1.0)
st.rerun()
