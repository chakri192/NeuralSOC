import streamlit as st
import pandas as pd
from shared.data_access import stream_manager
from dashboard.components.empty_states import render_no_alerts, render_broker_unavailable
from shared.formatters import categorize_evidence, format_timestamp, format_mitre, escape_markdown

st.set_page_config(page_title="Incident Queue", layout="wide")
st.title("Incident Investigation")

stream_manager.start_listeners()  # idempotent; see 1_Overview.py's comment
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

    # Streamlit calls format_func once per option on every rerender; the
    # previous lambda did three full-DataFrame boolean scans per option
    # (O(n^2) overall). set_index once and look up by label -- O(1) per
    # option -- which matters most exactly when incident volume is high,
    # i.e. mid-scan-or-DDoS, when the SOC is busiest.
    by_id = df.set_index("incident_id", drop=False)

    def _format_incident_option(incident_id):
        row = by_id.loc[incident_id]
        threat = row["threat_classes"][0] if row["threat_classes"] else "Unknown"
        return f"{row['severity'].upper()} ({row['risk_score']:.0f}) - {threat}"

    selected_id = st.selectbox(
        "Select Incident",
        options,
        format_func=_format_incident_option,
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
            related_ids = set(incident['related_alert_ids'])
            rel_alerts = [a for a in alerts if a['alert_id'] in related_ids]

            if not rel_alerts:
                st.info("Detailed signals have rotated out of the memory buffer.")
            else:
                for a in rel_alerts:
                    model_name = a.get("model_name") or "rule-based"
                    with st.expander(f"{format_timestamp(a['timestamp'])} | {a['threat_class']} ({model_name})"):
                        obs, inf, unk = categorize_evidence(a.get("evidence", {}))

                        col_o, col_i = st.columns(2)
                        with col_o:
                            st.markdown("##### Observed Facts")
                            for k, v in obs.items():
                                # Evidence values are attacker-influenced
                                # (a DNS query string, a JA4 fingerprint --
                                # anyone who can cause a query on the
                                # monitored network controls this) and must
                                # be escaped before interpolation.
                                st.markdown(f"- **{k}**: `{escape_markdown(v)}`")
                        with col_i:
                            st.markdown("##### Inferred & Model Outputs")
                            for k, v in inf.items():
                                st.markdown(f"- **{k}**: `{escape_markdown(v)}`")
                                
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
