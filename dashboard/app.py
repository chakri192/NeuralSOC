import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
# import time (unused)
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
            # unsafe_allow_html is safe here: content is a local static
            # file this repo ships, not user/network data. Without it the
            # whole stylesheet rendered as escaped text instead of
            # applying -- confirmed via `git log -S` this kwarg was
            # present before the commit that purged external GitHub
            # telemetry from this file, and was dropped only here.
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
    st.caption("ENV: DEMO")
with col3:
    st.caption("DIODE: ONE-WAY")
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
