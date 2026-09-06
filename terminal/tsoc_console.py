"""Terminal console for T-SOC: a keyboard-driven incident queue for an
analyst who lives in a terminal rather than a browser. Shares its
backend (shared/data_access.py), its triage persistence
(shared/triage_store.py), its login credential (shared/auth.py), and
its color palette (dashboard/theme.py) with the web dashboard, so
acknowledging an incident here shows up there and vice versa.
"""
import os
import secrets
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

import shared.triage_store as triage_store
from dashboard.theme import PALETTE, SEVERITY_COLORS, STATUS_COLORS
from shared.auth import resolve_dashboard_password
from shared.data_access import stream_manager
from shared.formatters import categorize_evidence, format_timestamp

_DASHBOARD_PASSWORD = resolve_dashboard_password(warn=True)

_STATUS_LABELS = {
    triage_store.OPEN: "OPEN",
    triage_store.ACKNOWLEDGED: "ACK",
    triage_store.FALSE_POSITIVE: "FALSE POS",
    triage_store.CONFIRMED: "CONFIRMED",
}


class LoginScreen(Screen):
    """Gates the console behind the same shared credential as the web
    dashboard -- one password for the whole product, not one per
    interface (see shared/auth.py)."""

    CSS = f"""
    LoginScreen {{
        align: center middle;
    }}
    #login-box {{
        width: 46;
        height: auto;
        padding: 1 2;
        border: solid {PALETTE["border"]};
        background: {PALETTE["surface"]};
    }}
    #login-title {{
        color: {PALETTE["accent"]};
        text-style: bold;
        padding-bottom: 1;
    }}
    #login-error {{
        color: {SEVERITY_COLORS["critical"]};
        height: 1;
        padding-top: 1;
    }}
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="login-box"):
            yield Static("T-SOC Console", id="login-title")
            yield Input(placeholder="Password", password=True, id="password-input")
            yield Static("", id="login-error")

    def on_mount(self) -> None:
        self.query_one("#password-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if secrets.compare_digest(event.value, _DASHBOARD_PASSWORD):
            self.app.push_screen(MainScreen())
        else:
            self.query_one("#login-error", Static).update("Incorrect password.")
            self.query_one("#password-input", Input).value = ""


class MainScreen(Screen):
    BINDINGS = [
        Binding("r", "refresh_data", "Refresh"),
        Binding("p", "toggle_pause", "Pause"),
        Binding("a", "acknowledge", "Ack"),
        Binding("f", "false_positive", "False Pos"),
        Binding("c", "confirm", "Confirm"),
        Binding("/", "start_filter", "Filter"),
        Binding("escape", "clear_filter", "Clear Filter", show=False),
    ]

    CSS = f"""
    #body {{
        height: 1fr;
    }}
    #queue {{
        width: 60%;
        height: 100%;
        border-right: solid {PALETTE["accent"]};
    }}
    #detail-pane {{
        width: 40%;
        height: 100%;
        padding: 1 2;
        overflow-y: auto;
    }}
    #filter-input {{
        height: 3;
        display: none;
        border: solid {PALETTE["border"]};
    }}
    #filter-input.-visible {{
        display: block;
    }}
    """

    def __init__(self) -> None:
        super().__init__()
        self.live_mode = True
        self._selected_incident_id = None
        self._filter_text = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield DataTable(id="queue")
            yield Static("Select an incident to view details.", id="detail-pane")
        yield Input(placeholder="Filter by severity, threat, or target...", id="filter-input")
        yield Footer()

    def on_mount(self) -> None:
        self.app.title = "T-SOC Console"
        queue = self.query_one("#queue", DataTable)
        queue.cursor_type = "row"
        queue.add_columns("SEV", "RISK", "THREAT", "TARGET", "STATUS")
        stream_manager.start_listeners()
        self.update_queue(force=True)
        self.update_timer = self.set_interval(2.0, self.update_queue)

    def action_toggle_pause(self) -> None:
        self.live_mode = not self.live_mode
        self._refresh_subtitle()

    def action_refresh_data(self) -> None:
        self.update_queue(force=True)

    def action_start_filter(self) -> None:
        filt = self.query_one("#filter-input", Input)
        filt.add_class("-visible")
        filt.focus()

    def action_clear_filter(self) -> None:
        filt = self.query_one("#filter-input", Input)
        if filt.has_class("-visible"):
            filt.value = ""
            filt.remove_class("-visible")
            self._filter_text = ""
            self.query_one("#queue", DataTable).focus()
            self.update_queue(force=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter-input":
            self._filter_text = event.value.strip().lower()
            self.update_queue(force=True)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter-input":
            self.query_one("#queue", DataTable).focus()

    def _current_actor(self) -> str:
        return os.getenv("USER") or os.getenv("USERNAME") or "analyst"

    def action_acknowledge(self) -> None:
        self._apply_triage(triage_store.ACKNOWLEDGED, "Acknowledged")

    def action_false_positive(self) -> None:
        self._apply_triage(triage_store.FALSE_POSITIVE, "Marked false positive")

    def action_confirm(self) -> None:
        self._apply_triage(triage_store.CONFIRMED, "Confirmed")

    def _apply_triage(self, status: str, label: str) -> None:
        if not self._selected_incident_id:
            self.notify("Select an incident first.", severity="warning")
            return
        triage_store.set_status(self._selected_incident_id, status, actor=self._current_actor())
        self.notify(f"{label}: {self._selected_incident_id}")
        self.update_queue(force=True)

    def _refresh_subtitle(self) -> None:
        healthy = stream_manager.status().get("broker_healthy", False)
        mode = "LIVE" if self.live_mode else "PAUSED"
        sensor = "HEALTHY" if healthy else "DOWN"
        self.app.sub_title = f"[{mode}] | DIODE: ONE-WAY | SENSOR: {sensor}"

    def update_queue(self, force: bool = False) -> None:
        if not self.live_mode and not force:
            return
        incidents = stream_manager.get_incidents()
        statuses = triage_store.get_all_statuses()
        queue = self.query_one("#queue", DataTable)
        queue.clear()
        incidents.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        needle = self._filter_text
        visible_ids = []
        for inc in incidents:
            sev = str(inc.get("severity", "low")).lower()
            threat = str(inc.get("threat_classes", ["Unknown"])[0])
            target = str(inc.get("affected_entities", ["Unknown"])[0])
            status = statuses.get(inc.get("incident_id"), {}).get("status", triage_store.OPEN)

            if needle and needle not in f"{sev} {threat} {target}".lower():
                continue

            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["low"])
            sev_styled = f"[{sev_color}]{sev.upper()}[/]"
            risk = f"{inc.get('risk_score', 0):.0f}"
            threat_disp = escape(threat)
            target_disp = target[:12] + "..." if len(target) > 15 else target
            target_disp = escape(target_disp)
            status_color = STATUS_COLORS.get(status, STATUS_COLORS[triage_store.OPEN])
            status_label = _STATUS_LABELS.get(status, status.upper())
            status_styled = f"[{status_color}]{status_label}[/]"

            incident_id = inc.get("incident_id")
            queue.add_row(sev_styled, risk, threat_disp, target_disp, status_styled, key=incident_id)
            visible_ids.append(incident_id)

        self._refresh_subtitle()

        if self._selected_incident_id in visible_ids:
            queue.move_cursor(row=queue.get_row_index(self._selected_incident_id))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        incident_id = event.row_key.value
        self._selected_incident_id = incident_id
        incidents = stream_manager.get_incidents()
        all_alerts = stream_manager.get_alerts()
        inc = next((i for i in incidents if i.get("incident_id") == incident_id), None)
        if not inc:
            return
        detail = self.query_one("#detail-pane", Static)
        summary = escape(str(inc.get("evidence_summary", "")))
        tactics = escape(", ".join(inc.get("mitre_tactics", [])))
        ts = format_timestamp(inc.get("created_timestamp", ""))
        related_ids = inc.get("related_alert_ids", [])
        related_alerts = [a for a in all_alerts if a.get("alert_id") in related_ids]

        observed_lines = []
        inferred_lines = []
        for a in related_alerts:
            obs, inf, _unk = categorize_evidence(a.get("evidence", {}))
            for k, v in obs.items():
                observed_lines.append(f"- {escape(k.replace('_', ' ').title())}: {escape(str(v))}")
            for k, v in inf.items():
                inferred_lines.append(f"- {escape(k.replace('_', ' ').title())}: {escape(str(v))}")
            if a.get("model_name"):
                inferred_lines.append(
                    f"- {escape(str(a.get('model_name')))} flagged {escape(str(a.get('threat_class', 'Threat')))} "
                    f"(Conf: {a.get('confidence_score', 0) * 100:.0f}%)"
                )

        observed_text = "\n".join(dict.fromkeys(observed_lines)) or "- No raw metadata facts extracted."
        inferred_text = "\n".join(dict.fromkeys(inferred_lines)) or "- Rule-based heuristic, no ML models triggered."

        triage = triage_store.get_status(incident_id)
        status_label = _STATUS_LABELS.get(triage["status"], triage["status"].upper())

        content = f"""
[b]Incident:[/] {incident_id}
[b]Status:[/] {status_label}
[b]Severity:[/] {inc.get('severity', 'low').upper()}
[b]Risk Score:[/] {inc.get('risk_score', 0):.1f}
[b]First seen:[/] {ts}

[b]Automated Summary:[/]
{summary}

[b][{PALETTE["accent"]}]Observed Facts:[/][/]
{observed_text}

[b][{SEVERITY_COLORS["high"]}]Inferred ML Findings:[/][/]
{inferred_text}

[b][{PALETTE["text-muted"]}]Unknowns:[/][/]
- Payload contents were not inspected (Data Diode boundary).
- Endpoint process identity is unavailable.

[b]ATT&CK Mappings:[/] {tactics}
[b]Related Alerts:[/] {len(related_ids)}
        """
        detail.update(content)
        if self.live_mode:
            self.action_toggle_pause()
            self.notify("Paused live updates for investigation.")


class TSOCConsole(App):
    CSS = f"""
    Screen {{
        background: {PALETTE["bg"]};
    }}
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def on_mount(self) -> None:
        self.title = "T-SOC Console"
        self.push_screen(LoginScreen())


if __name__ == "__main__":
    app = TSOCConsole()
    app.run()
