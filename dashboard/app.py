import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
import time
from datetime import datetime, timezone

from shared.data_access import stream_manager
from dashboard.components.empty_states import render_broker_unavailable

st.set_page_config(
    page_title="T-SOC Operations Center",
    layout="wide",
    initial_sidebar_state="expanded"
)

def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "styles", "app.css")
    if os.path.exists(css_path):
        with open(css_path, "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# Start background data ingestion globally
stream_manager.start_listeners()
status = stream_manager.status()



# Top bar layout - Professional Header
col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
with col1:
    st.markdown("##  T-SOC Platform")
with col2:
    st.markdown("<br>**ENV:** <span style='color:#7aa2f7'>DEMO</span>", unsafe_allow_html=True)
with col3:
    st.markdown("<br>**DIODE:** <span style='color:#9ece6a'>ONE-WAY</span>", unsafe_allow_html=True)
with col4:
    current_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    st.markdown(f"<br>**TIME:** `{current_utc}`", unsafe_allow_html=True)

st.markdown("---")

if not status["broker_healthy"]:
    render_broker_unavailable()
else:
    st.success("System Health: ONLINE | Inference Engine: ACTIVE | Select a module from the sidebar.")

st.markdown("""
### Core Principles
This interface is optimized for decision-making under pressure. 
* Events are grouped into Correlated Incidents. 
* Actions are approval-gated and read-only.
* ML inferences are strictly separated from observed network facts.
""")
