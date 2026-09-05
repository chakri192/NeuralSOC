import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from shared.data_access import stream_manager
from dashboard.components.empty_states import render_no_alerts, render_broker_unavailable

st.set_page_config(page_title="Network Graph", layout="wide")
st.title("Network Relationships")

stream_manager.start_listeners()  # idempotent; see 1_Overview.py's comment
status = stream_manager.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

alerts = stream_manager.get_alerts()
if not alerts:
    render_no_alerts()
    st.stop()

df = pd.DataFrame(alerts)

# Filters to restrict node count
st.sidebar.subheader("Graph Filters")
min_confidence = st.sidebar.slider("Min Confidence Score", 0.0, 1.0, 0.5)
max_nodes = st.sidebar.slider("Max Nodes to Render", 10, 100, 30)

filtered_df = df[df['confidence_score'] >= min_confidence]

if filtered_df.empty:
    st.info("No connections meet the current filter criteria.")
    st.stop()

# Aggregate relationships
relationships = filtered_df.groupby(['source_ip', 'destination_ip']).size().reset_index(name='weight')
relationships = relationships.sort_values(by='weight', ascending=False).head(max_nodes)

st.markdown("""
Visualizing directional connections between sources and destinations. 
*Node relationships are capped to prevent browser exhaustion.*
""")

tab_graph, tab_table = st.tabs(["Sankey Diagram", "Tabular View"])

with tab_graph:
    # Build Sankey mapping
    all_nodes = list(pd.unique(relationships[['source_ip', 'destination_ip']].values.ravel('K')))
    node_mapping = {node: i for i, node in enumerate(all_nodes)}
    
    relationships['source_idx'] = relationships['source_ip'].map(node_mapping)
    relationships['dest_idx'] = relationships['destination_ip'].map(node_mapping)
    
    fig = go.Figure(data=[go.Sankey(
        node = dict(
          pad = 15,
          thickness = 20,
          line = dict(color = "black", width = 0.5),
          label = all_nodes,
          color = "#00bcd4"
        ),
        link = dict(
          source = relationships['source_idx'],
          target = relationships['dest_idx'],
          value = relationships['weight'],
          color = "rgba(245, 124, 0, 0.4)" # High severity orange, translucent
        )
    )])
    
    fig.update_layout(height=600, margin=dict(l=0, r=0, t=30, b=0), font_color="white")
    st.plotly_chart(fig, use_container_width=True)

with tab_table:
    st.dataframe(relationships[['source_ip', 'destination_ip', 'weight']], use_container_width=True)
