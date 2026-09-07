"""The primary, daily-use screen: KPI strip + incident queue + a detail
panel that opens in-place when a row is selected (no page navigation).
Replaces the old 1_Overview.py (decorative charts) and 2_Incidents.py
(separate page for the same queue) with one view, because in every real
SOC tool this is modeled on (Splunk ES, Sentinel, Elastic Security) the
queue *is* the app -- everything else is secondary.
"""
import html
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pandas as pd
import streamlit as st

import shared.triage_store as triage_store
from dashboard import session_data
from dashboard.components.empty_states import render_broker_unavailable, render_no_alerts
from dashboard.components.ui import kpi_card, kpi_row, relative_time, render_evidence_columns, severity_badge, status_badge
from dashboard.theme import SEVERITY_ORDER, STATUS_LABELS
from shared.formatters import format_timestamp

status = session_data.status()
if not status["broker_healthy"]:
    render_broker_unavailable()
    st.stop()

incidents = session_data.get_incidents()
if not incidents:
    render_no_alerts()
    st.stop()

df = pd.DataFrame(incidents)
triage = triage_store.get_all_statuses(st.session_state["access_token"])
df["triage_status"] = df["incident_id"].map(lambda i: triage.get(i, {}).get("status", triage_store.OPEN))

st.markdown("## Operations Overview")
with st.container(key="refresh_corner"):
    if st.button("", icon=":material/refresh:", help="Refresh"):
        st.rerun()

# ---------- KPI strip (reflects the full incident set, not the filtered queue below) ----------

open_mask = df["triage_status"] == triage_store.OPEN
active_mask = df["triage_status"] != triage_store.FALSE_POSITIVE

kpi_row([
    kpi_card("Needs Triage", str(int(open_mask.sum())), tone="accent", sublabel="untouched incidents"),
    kpi_card("Critical", str(int((df["severity"] == "critical").sum())), tone="critical"),
    kpi_card("High", str(int((df["severity"] == "high").sum())), tone="high"),
    kpi_card("Total Active", str(int(active_mask.sum())), tone="neutral", sublabel=f"{len(df)} total, {int((~active_mask).sum())} dismissed"),
    kpi_card("Avg Risk Score", f"{df.loc[active_mask, 'risk_score'].mean():.0f}" if active_mask.any() else "0", tone="accent"),
])

# ---------- Filter bar ----------

st.markdown('<div class="tsoc-panel__title">Incident Queue</div>', unsafe_allow_html=True)
f1, f2 = st.columns(2)
with f1:
    severity_filter = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
with f2:
    status_filter = st.multiselect(
        "Triage status",
        list(STATUS_LABELS.keys()),
        default=[triage_store.OPEN, triage_store.ACKNOWLEDGED, triage_store.CONFIRMED],
        format_func=lambda s: STATUS_LABELS[s],
    )
search = st.text_input(
    "Search incident ID, entity, or threat class",
    placeholder="e.g. 10.0.0.5, DGA, INC-...",
    key="incident_search",
)

filtered = df[df["severity"].isin(severity_filter) & df["triage_status"].isin(status_filter)]
if search:
    needle = search.strip().lower()

    def _matches(row) -> bool:
        haystack = " ".join([
            str(row["incident_id"]),
            " ".join(row["threat_classes"]),
            " ".join(row["affected_entities"]),
        ]).lower()
        return needle in haystack

    filtered = filtered[filtered.apply(_matches, axis=1)]

filtered = filtered.sort_values(by=["risk_score", "created_timestamp"], ascending=[False, False]).reset_index(drop=True)

if filtered.empty:
    st.info("No incidents match the current filters.")
    st.stop()

display_df = pd.DataFrame({
    "First Seen": filtered["created_timestamp"].apply(relative_time),
    "Severity": filtered["severity"].str.upper(),
    "Risk": filtered["risk_score"],
    "Threat Class": filtered["threat_classes"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x),
    "Entities": filtered["affected_entities"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x),
    "Status": filtered["triage_status"].map(STATUS_LABELS),
})

_SEVERITY_BG = {"CRITICAL": "#e5484d", "HIGH": "#f5a524", "MEDIUM": "#f5d90a", "LOW": "#6b7785"}
_STATUS_TEXT = {"Open": "#3b82f6", "Acknowledged": "#3b82f6", "Confirmed": "#e5484d", "False Positive": "#8b93a1"}


def _style_severity(val):
    color = _SEVERITY_BG.get(val, "#6b7785")
    return f"color: {color}; font-weight: 700;"


def _style_status(val):
    color = _STATUS_TEXT.get(val, "#8b93a1")
    return f"color: {color}; font-weight: 600;"


styled = display_df.style.map(_style_severity, subset=["Severity"]).map(_style_status, subset=["Status"])

event = st.dataframe(
    styled,
    hide_index=True,
    height=min(440, 46 + 36 * len(display_df)),
    column_config={
        "Risk": st.column_config.ProgressColumn("Risk", format="%.0f", min_value=0, max_value=100),
    },
    on_select="rerun",
    selection_mode="single-row",
    key="incident_queue_table",
)

selected_rows = event.selection.rows if event and event.selection else []
if not selected_rows:
    st.caption("Select a row above to open its detail panel.")
    st.stop()

incident = filtered.iloc[selected_rows[0]].to_dict()
current_triage = triage.get(incident["incident_id"], {"status": triage_store.OPEN, "note": "", "actor": "", "updated_at": ""})

st.markdown("---")

header_l, header_r = st.columns([4, 1])
with header_l:
    st.markdown(f"### {incident['threat_classes'][0] if incident['threat_classes'] else 'Unclassified Threat'}")
    st.markdown(
        f'<span class="tsoc-mono">{incident["incident_id"]}</span> &nbsp;·&nbsp; '
        f'{severity_badge(incident["severity"])} &nbsp; {status_badge(current_triage["status"])}',
        unsafe_allow_html=True,
    )
with header_r:
    if current_triage["actor"]:
        st.caption(f"Last updated by {current_triage['actor']}")

kc1, kc2, kc3 = st.columns(3)
kc1.metric("Risk Score (of 100)", f"{incident['risk_score']:.0f}")
kc2.metric("First Seen", relative_time(incident["created_timestamp"]))
kc3.metric("Signals", len(incident.get("related_alert_ids", [])))

st.markdown(f'<span class="tsoc-mono">Affected: {html.escape(", ".join(incident["affected_entities"]))}</span>', unsafe_allow_html=True)

tab_summary, tab_evidence, tab_attack, tab_actions = st.tabs(["Summary", "Evidence", "ATT&CK Mapping", "Analyst Actions"])

with tab_summary:
    st.markdown(incident["evidence_summary"])

with tab_evidence:
    alerts = session_data.get_alerts()
    related_ids = set(incident.get("related_alert_ids", []))
    rel_alerts = [a for a in alerts if a["alert_id"] in related_ids]

    if not rel_alerts:
        st.info("Detailed signals have rotated out of the memory buffer.")
    else:
        for a in rel_alerts:
            model_name = a.get("model_name") or "rule-based"
            with st.expander(f"{format_timestamp(a['timestamp'])} · {a['threat_class']} ({model_name})"):
                render_evidence_columns(a.get("evidence", {}))

with tab_attack:
    for tactic in incident.get("mitre_tactics", []):
        st.markdown(f"- **Tactic:** {tactic}")
    for tech in incident.get("mitre_techniques", []):
        st.markdown(f"- **Technique:** `{tech}`")

with tab_actions:
    st.info("Automated containment actions are disabled (read-only data diode). These actions record analyst triage state only.")
    note = st.text_input("Note (optional)", value=current_triage.get("note", ""), key=f"note_{incident['incident_id']}")

    a1, a2, a3 = st.columns(3)

    def _set(new_status: str, label: str):
        # actor is no longer a parameter here -- the API derives it from
        # this session's own JWT (st.session_state["access_token"]),
        # not a client-supplied string nothing used to verify.
        triage_store.set_status(st.session_state["access_token"], incident["incident_id"], new_status, note=note)
        st.toast(f"{label}: {incident['incident_id']}", icon=":material/check_circle:")
        st.rerun()

    if a1.button("Acknowledge", width="stretch"):
        _set(triage_store.ACKNOWLEDGED, "Acknowledged")
    if a2.button("Mark False Positive", width="stretch"):
        _set(triage_store.FALSE_POSITIVE, "Marked false positive")
    if a3.button("Confirm & Escalate", type="primary", width="stretch"):
        _set(triage_store.CONFIRMED, "Confirmed and escalated")
