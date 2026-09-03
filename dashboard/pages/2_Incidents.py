import streamlit as st
import pandas as pd
from shared.data_access import stream_manager
from dashboard.components.empty_states import render_no_alerts, render_broker_unavailable
from shared.formatters import categorize_evidence, format_timestamp, format_mitre

st.set_page_config(page_title="Incident Queue", layout="wide")
st.title("Incident Investigation")

status = stream_manager.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

incidents = stream_manager.get_incidents()
if not incidents:
    render_no_alerts()
    st.stop()

df = pd.DataFrame(incidents)
df = df.sort_values(by="risk_score", ascending=False)

# Workflow: Queue on left, Details on right
col_queue, col_detail = st.columns([1, 3])

with col_queue:
    st.subheader("Needs Attention")
    # Format a compact view for the dropdown
    options = df["incident_id"].tolist()
    
    selected_id = st.selectbox(
        "Select Incident",
        options,
        format_func=lambda x: f"{df[df['incident_id']==x]['severity'].iloc[0].upper()} ({df[df['incident_id']==x]['risk_score'].iloc[0]:.0f}) - {df[df['incident_id']==x]['threat_classes'].iloc[0][0]}" if not df[df['incident_id']==x].empty else x
    )

if selected_id:
    incident = df[df["incident_id"] == selected_id].iloc[0].to_dict()
    
    with col_detail:
        # Header block
        st.subheader(f"{incident['threat_classes'][0] if incident['threat_classes'] else 'Unknown Threat'}")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk Score", f"{incident['risk_score']}/100")
        c2.metric("Severity", incident['severity'].upper())
        c3.metric("First Seen", format_timestamp(incident['created_timestamp']))
        c4.metric("Status", incident['status'].upper())
        
        st.markdown(f"**Affected Entities:** `{', '.join(incident['affected_entities'])}`")
        st.markdown("---")
        
        # Tabs for Progressive Disclosure
        tab_summary, tab_evidence, tab_attack, tab_actions = st.tabs(["Summary", "Evidence", "ATT&CK Mapping", "Analyst Actions"])
        
        with tab_summary:
            st.markdown(f"**Automated Summary**\n> {incident['evidence_summary']}")
            
        with tab_evidence:
            st.markdown("### Related Signals")
            alerts = stream_manager.get_alerts()
            rel_alerts = [a for a in alerts if a['alert_id'] in incident['related_alert_ids']]
            
            if not rel_alerts:
                st.info("Detailed signals have rotated out of the memory buffer.")
            else:
                for a in rel_alerts:
                    with st.expander(f"{format_timestamp(a['timestamp'])} | {a['threat_class']} ({a['model_name']})"):
                        obs, inf, unk = categorize_evidence(a.get("evidence", {}))
                        
                        col_o, col_i = st.columns(2)
                        with col_o:
                            st.markdown("##### Observed Facts")
                            for k, v in obs.items():
                                st.markdown(f"- **{k}**: `{v}`")
                        with col_i:
                            st.markdown("##### Inferred & Model Outputs")
                            for k, v in inf.items():
                                st.markdown(f"- **{k}**: `{v}`")
                                
        with tab_attack:
            st.markdown("### MITRE ATT&CK Mappings")
            for tactic in incident.get("mitre_tactics", []):
                st.markdown(f"- **Tactic:** {tactic}")
            for tech in incident.get("mitre_techniques", []):
                st.markdown(f"- **Technique:** `{tech}`")
                
        with tab_actions:
            st.warning("All automated containment actions are disabled (Read-Only Data Diode active).")
            st.button("Acknowledge Incident")
            st.button("Mark as False Positive")
            st.button("Mark as Confirmed (Escalate)")
