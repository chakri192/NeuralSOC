"""Terminal console for T-SOC: a keyboard-driven incident queue for an
analyst who lives in a terminal rather than a browser. Shares its
backend (the same FastAPI /api/v1/alerts, /api/v1/triage endpoints the
web dashboard calls), its login (api/routes/auth.py's /auth/login --
the same per-employee account, not a separate shared password), and its
color palette (dashboard/theme.py) with the web dashboard, so
acknowledging an incident here shows up there and vice versa, scoped to
whichever tenant the logged-in analyst belongs to.

Reads alerts via shared/data_access.py's fetch_alerts(), not
DataStreamManager -- that class is a process-wide singleton keyed to a
single static service key (fine for dashboard/cli_dashboard.py's
single-operator terminal tool), which can't hold a distinct token per
logged-in analyst.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

import shared.triage_store as triage_store
from dashboard.theme import PALETTE, SEVERITY_COLORS, STATUS_COLORS
from shared.data_access import fetch_alerts, synthesize_incidents
from shared.formatters import categorize_evidence, format_timestamp

_API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1")
_REQUEST_TIMEOUT_SEC = 5

_STATUS_LABELS = {
    triage_store.OPEN: "OPEN",
    triage_store.ACKNOWLEDGED: "ACK",
    triage_store.FALSE_POSITIVE: "FALSE POS",
    triage_store.CONFIRMED: "CONFIRMED",
}


class LoginScreen(Screen):
    """Gates the console behind the same per-employee account as the web
    dashboard (api/routes/auth.py's /auth/login) -- one identity system
    for the whole product, not a separate shared password for this
    interface."""

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
            yield Input(placeholder="Email", id="email-input")
            yield Input(placeholder="Password", password=True, id="password-input")
            yield Static("", id="login-error")

    def on_mount(self) -> None:
        self.query_one("#email-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "email-input":
            self.query_one("#password-input", Input).focus()
            return
        self._attempt_login()

    def _attempt_login(self) -> None:
        email = self.query_one("#email-input", Input).value.strip()
        password = self.query_one("#password-input", Input).value
        error = self.query_one("#login-error", Static)
        try:
            resp = requests.post(
                f"{_API_URL}/auth/login", json={"email": email, "password": password}, timeout=_REQUEST_TIMEOUT_SEC
            )
        except requests.RequestException:
            error.update("Could not reach the T-SOC API.")
            return
        if resp.status_code == 200:
            token = resp.json()["access_token"]
            self.app.push_screen(MainScreen(token=token, analyst_email=email))
        elif resp.status_code == 429:
            error.update("Too many failed attempts. Try again later.")
        else:
            error.update("Incorrect email or password.")
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

    def __init__(self, token: str, analyst_email: str) -> None:
        super().__init__()
        self._token = token
        self._analyst_email = analyst_email
        self.live_mode = True
        self._healthy = True
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
        self.app.title = f"T-SOC Console -- {self._analyst_email}"
        queue = self.query_one("#queue", DataTable)
        queue.cursor_type = "row"
        queue.add_columns("SEV", "RISK", "THREAT", "TARGET", "STATUS")
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
        try:
            triage_store.set_status(self._token, self._selected_incident_id, status)
        except requests.RequestException as ex:
            self.notify(f"Failed to update triage: {ex}", severity="error")
            return
        self.notify(f"{label}: {self._selected_incident_id}")
        self.update_queue(force=True)

    def _refresh_subtitle(self) -> None:
        mode = "LIVE" if self.live_mode else "PAUSED"
        sensor = "HEALTHY" if self._healthy else "DOWN"
        self.app.sub_title = f"[{mode}] | DIODE: ONE-WAY | SENSOR: {sensor}"

    def update_queue(self, force: bool = False) -> None:
        if not self.live_mode and not force:
            return
        try:
            alerts = fetch_alerts(self._token)
            statuses = triage_store.get_all_statuses(self._token)
            self._healthy = True
        except requests.RequestException as ex:
            self._healthy = False
            self._refresh_subtitle()
            self.notify(f"Refresh failed: {ex}", severity="error")
            return

        incidents = synthesize_incidents(alerts)
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
            sev_styled = f"[{sev_color}]{escape(sev.upper())}[/]"
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
        try:
            alerts = fetch_alerts(self._token)
            triage = triage_store.get_status(self._token, incident_id)
        except requests.RequestException as ex:
            self.notify(f"Failed to load incident detail: {ex}", severity="error")
            return

        incidents = synthesize_incidents(alerts)
        inc = next((i for i in incidents if i.get("incident_id") == incident_id), None)
        if not inc:
            return
        detail = self.query_one("#detail-pane", Static)
        summary = escape(str(inc.get("evidence_summary", "")))
        tactics = escape(", ".join(inc.get("mitre_tactics", [])))
        ts = format_timestamp(inc.get("created_timestamp", ""))
        related_ids = inc.get("related_alert_ids", [])
        related_alerts = [a for a in alerts if a.get("alert_id") in related_ids]

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

        status_label = _STATUS_LABELS.get(triage["status"], triage["status"].upper())

        content = f"""
[b]Incident:[/] {escape(str(incident_id))}
[b]Status:[/] {status_label}
[b]Severity:[/] {escape(str(inc.get('severity', 'low')).upper())}
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
