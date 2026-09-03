import os
import sys
from datetime import datetime, timezone

# Ensure parent directory is in path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Label
from textual.containers import Horizontal, Vertical
from textual.binding import Binding

from shared.data_access import stream_manager
from shared.formatters import categorize_evidence, format_timestamp

class TSOCConsole(App):
    """Keyboard-first Terminal SOC Console optimized for SSH and narrow displays."""
    
    CSS = """
    Screen { background: #1e1e24; }
    DataTable { width: 50%; height: 100%; border-right: solid #00bcd4; }
    #detail-pane { width: 50%; height: 100%; padding: 1 2; overflow-y: auto; }
    
    .critical { color: red; text-style: bold; }
    .high { color: darkorange; text-style: bold; }
    .medium { color: yellow; }
    .low { color: lightblue; }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh_data", "Refresh"),
        Binding("p", "toggle_pause", "Pause Live Mode"),
        Binding("a", "acknowledge", "Ack Incident"),
    ]

    def __init__(self):
        super().__init__()
        self.live_mode = True

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield DataTable(id="queue")
            yield Static("Select an incident to view details.", id="detail-pane")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "T-SOC Console"
        self.sub_title = "[LIVE] | DIODE: ONE-WAY | SENSOR: HEALTHY"
        
        queue = self.query_one("#queue", DataTable)
        queue.cursor_type = "row"
        queue.add_columns("SEV", "RISK", "THREAT", "TARGET")
        
        # Start background Kafka threads via shared StreamManager
        stream_manager.start_listeners()
        
        # Poll local memory buffer periodically
        self.update_timer = self.set_interval(2.0, self.update_queue)

    def action_toggle_pause(self) -> None:
        self.live_mode = not self.live_mode
        self.sub_title = "[LIVE] | DIODE: ONE-WAY" if self.live_mode else "[PAUSED]"

    def action_refresh_data(self) -> None:
        self.update_queue(force=True)

    def action_acknowledge(self) -> None:
        self.notify("Action 'Acknowledge' is simulated (Read-Only Mode active).")

    def update_queue(self, force=False) -> None:
        if not self.live_mode and not force:
            return
            
        incidents = stream_manager.get_incidents()
        queue = self.query_one("#queue", DataTable)
        
        # Save cursor to prevent jarring UI jumps during live updates
        current_row = queue.cursor_row
        queue.clear()
        
        # Sort highest risk first
        incidents.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        
        for inc in incidents:
            sev = inc.get("severity", "low").upper()
            sev_styled = f"[{sev.lower()}]{sev}[/]"
            risk = f"{inc.get('risk_score', 0):.0f}"
            threat = escape(str(inc.get("threat_classes", ["Unknown"])[0]))
            
            target = escape(str(inc.get("affected_entities", ["Unknown"])[0]))
            if len(target) > 15:
                target = target[:12] + "..."
                
            queue.add_row(sev_styled, risk, threat, target, key=inc.get("incident_id"))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        incident_id = event.row_key.value
        incidents = stream_manager.get_incidents()
        all_alerts = stream_manager.get_alerts()
        
        inc = next((i for i in incidents if i.get("incident_id") == incident_id), None)
        if not inc: return
        
        detail = self.query_one("#detail-pane", Static)
        
        summary = escape(str(inc.get("evidence_summary", "")))
        tactics = escape(", ".join(inc.get("mitre_tactics", [])))
        ts = format_timestamp(inc.get('created_timestamp', ''))
        
        related_ids = inc.get('related_alert_ids', [])
        related_alerts = [a for a in all_alerts if a.get('alert_id') in related_ids]
        
        # Build Evidence Narrative
        observed = []
        inferred = []
        for a in related_alerts:
            t = a.get("threat_class", "Threat")
            for k, v in a.get("evidence", {}).items():
                if k == "inference_latency_ms":
                    inferred.append(f"- Model inference took {v:.1f}ms for {t}")
                elif k == "shannon_entropy":
                    observed.append(f"- DNS query Shannon Entropy measured at {v:.2f}")
                else:
                    observed.append(f"- {escape(k.replace('_', ' ').title())}: {escape(str(v))}")
                    
            if a.get("model_name"):
                inferred.append(f"- {escape(str(a.get('model_name')))} flagged {escape(t)} (Conf: {a.get('confidence_score',0)*100:.0f}%)")
        
        observed_text = "\n".join(set(observed)) if observed else "- No raw metadata facts extracted."
        inferred_text = "\n".join(set(inferred)) if inferred else "- Rule-based heuristic, no ML models triggered."
        
        content = f"""
[b]Incident:[/] {incident_id}
[b]Status:[/] {inc.get('status', 'NEW').upper()}
[b]Severity:[/] {inc.get('severity', 'LOW').upper()}
[b]Risk Score:[/] {inc.get('risk_score', 0):.1f}
[b]First seen:[/] {ts}

[b]Automated Summary:[/]\n{summary}

[b][#00bcd4]Observed Facts:[/#00bcd4][/]
{observed_text}

[b][#ff9800]Inferred ML Findings:[/#ff9800][/]
{inferred_text}

[b][#9e9e9e]Unknowns:[/#9e9e9e][/]
- Payload contents were not inspected (Data Diode boundary).
- Endpoint process identity is unavailable.

[b]ATT&CK Mappings:[/]\n{tactics}
[b]Related Alerts:[/] {len(related_ids)}
        """
        detail.update(content)
        
        # Automatically pause live mode when analyzing a detail pane
        if self.live_mode:
            self.action_toggle_pause()
            self.notify("Paused live updates for investigation.")

if __name__ == "__main__":
    app = TSOCConsole()
    app.run()
