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
            body = resp.json()
            if body.get("mfa_required"):
                # api/routes/auth.py's login() returns a challenge, not a
                # session, once MFA is enabled for this account -- this
                # console has no code prompt to complete it with yet
                # (dashboard/app.py does). Fail loudly and clearly rather
                # than crash on the missing access_token below.
                error.update("MFA is enabled for this account. Sign in via the web dashboard instead.")
                return
            self.app.push_screen(MainScreen(token=body["access_token"], analyst_email=email))
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
        # Quick severity filters -- same substring-match filter box the "/"
        # key opens, just pre-filled instead of typed. Digits chosen since
        # 1-4 map naturally to critical-through-low without colliding with
        # any letter already bound above.
        Binding("1", "filter_severity('critical')", "Crit", show=False),
        Binding("2", "filter_severity('high')", "High", show=False),
        Binding("3", "filter_severity('medium')", "Med", show=False),
        Binding("4", "filter_severity('low')", "Low", show=False),
        # Quick status filters -- shift of the matching action letter (Ack
        # is "a", filtering to ACKNOWLEDGED is "A"; same for confirm/false
        # positive), plus "O" for the one status with no action key of its
        # own (nothing "opens" an incident -- it just starts that way).
        Binding("O", "filter_status('open')", "Open", show=False),
        Binding("A", "filter_status('acknowledged')", "Ack'd", show=False),
        Binding("C", "filter_status('confirmed')", "Conf'd", show=False),
        Binding("F", "filter_status('false_positive')", "False Pos'd", show=False),
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
        # Full incident dict for whichever incident is currently selected,
        # captured the last time it actually appeared in a fetch -- see
        # its use in update_queue() below for why this exists.
        self._selected_incident_cache = None
        # The exact alert list that produced whatever's currently on
        # screen -- see update_queue()'s and on_data_table_row_selected()'s
        # comments for why detail lookups reuse this instead of re-fetching.
        self._last_alerts = []

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

    def _set_filter(self, text: str) -> None:
        """Shared by the severity/status quick-keys below: fills and shows
        the same filter box "/" opens, rather than a separate filtering
        code path -- so Escape (action_clear_filter) already knows how to
        clear it, and it participates in the exact same substring match
        every other filter term does."""
        filt = self.query_one("#filter-input", Input)
        filt.value = text
        filt.add_class("-visible")
        self._filter_text = text
        self.update_queue(force=True)

    def action_filter_severity(self, severity: str) -> None:
        self._set_filter(severity)

    def action_filter_status(self, status: str) -> None:
        self._set_filter(_STATUS_LABELS.get(status, status).lower())

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

        # Reused by on_data_table_row_selected() below instead of it doing
        # a second, independent fetch_alerts() call of its own -- with
        # continuous live traffic, that second fetch can legitimately
        # disagree with the one that just populated the table a moment
        # ago (the 100-alert window has already moved on), so a row that
        # visibly just appeared could 404 out of its own detail lookup and
        # silently do nothing on Enter. This guarantees whatever's on
        # screen is exactly what gets looked up -- no second race to lose.
        self._last_alerts = alerts

        incidents = synthesize_incidents(alerts)

        # fetch_alerts() returns only the latest 100 alerts (the API's own
        # server-side cap), and incidents are grouped by source IP -- under
        # real, continuous traffic across many distinct sources (confirmed:
        # 200+ distinct source IPs churning through that 100-row window in
        # this demo), the specific incident an analyst has selected and
        # paused on to investigate can fall out of that window within
        # seconds, well before they finish reading it or act on it. Without
        # this, it would simply vanish from `incidents` below, the cursor-
        # restoration logic a few lines down would silently fail its `in
        # visible_ids` check, and the selection would appear to jump to an
        # unrelated row the moment the analyst acknowledged/confirmed/
        # dismissed it -- exactly the bug reported live. Splicing the last-
        # known copy back in keeps it on screen (with its status still read
        # fresh from triage_store below, which isn't windowed) until the
        # analyst moves their selection elsewhere.
        selected_ids = {inc.get("incident_id") for inc in incidents}
        if self._selected_incident_id in selected_ids:
            self._selected_incident_cache = next(
                inc for inc in incidents if inc.get("incident_id") == self._selected_incident_id
            )
        elif self._selected_incident_id and self._selected_incident_cache:
            incidents.append(self._selected_incident_cache)

        queue = self.query_one("#queue", DataTable)
        queue.clear()
        incidents.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        needle = self._filter_text
        visible_ids = []
        for inc in incidents:
            sev = str(inc.get("severity", "low")).lower()
            threat = str(inc.get("threat_classes", ["Unknown"])[0])
            target = str(inc.get("affected_entities", ["Unknown"])[0])
            incident_id = inc.get("incident_id", "")
            status = statuses.get(incident_id, {}).get("status", triage_store.OPEN)
            status_label = _STATUS_LABELS.get(status, status.upper())
            # incident_id is literally "INC-" + the source IP with dots
            # swapped for dashes (see synthesize_incidents) -- reversing
            # that gives a real, dotted source IP an analyst can type
            # straight into the filter box, without needing "affected_entities"
            # (an unordered set mixing source *and* destination IPs, so its
            # first element was never reliably the source anyway).
            source_ip = incident_id[4:].replace("-", ".") if incident_id.startswith("INC-") else ""

            haystack = f"{sev} {threat} {target} {source_ip} {status_label}".lower()
            if needle and needle not in haystack:
                continue

            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["low"])
            sev_styled = f"[{sev_color}]{escape(sev.upper())}[/]"
            risk = f"{inc.get('risk_score', 0):.0f}"
            threat_disp = escape(threat)
            target_disp = target[:12] + "..." if len(target) > 15 else target
            target_disp = escape(target_disp)
            status_color = STATUS_COLORS.get(status, STATUS_COLORS[triage_store.OPEN])
            status_styled = f"[{status_color}]{status_label}[/]"

            queue.add_row(sev_styled, risk, threat_disp, target_disp, status_styled, key=incident_id)
            visible_ids.append(incident_id)

        self._refresh_subtitle()

        if self._selected_incident_id in visible_ids:
            queue.move_cursor(row=queue.get_row_index(self._selected_incident_id))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        incident_id = event.row_key.value
        if incident_id != self._selected_incident_id:
            # Moving to a different incident -- drop the previous one's
            # pinned copy (see update_queue()) so it stops being kept
            # alive on screen after the analyst has moved on from it.
            self._selected_incident_cache = None
        self._selected_incident_id = incident_id
        # Reuse the exact snapshot that put this row on screen (see
        # update_queue()'s comment) rather than fetching alerts again here
        # -- a second, independent fetch under continuous live traffic can
        # legitimately disagree with the first, so a row that just
        # appeared could otherwise fail to find itself and silently do
        # nothing. Per-incident triage status isn't windowed the same way,
        # so that lookup stays a fresh call.
        alerts = self._last_alerts
        try:
            triage = triage_store.get_status(self._token, incident_id)
        except requests.RequestException as ex:
            self.notify(f"Failed to load incident detail: {ex}", severity="error")
            return

        incidents = synthesize_incidents(alerts)
        inc = next((i for i in incidents if i.get("incident_id") == incident_id), None)
        if not inc and self._selected_incident_cache and self._selected_incident_cache.get("incident_id") == incident_id:
            # This row exists on screen only because update_queue() pinned
            # it there after it aged out of the live window entirely (see
            # that method's own comment) -- its alerts were never going to
            # be in this fetch either. Fall back to the aggregate summary
            # already captured in the cache; the per-alert evidence lines
            # below will correctly come up empty rather than the whole
            # lookup silently doing nothing.
            inc = self._selected_incident_cache
        if not inc:
            return
        # Seed the pin cache right here, at selection time -- not just
        # opportunistically inside update_queue() -- because viewing an
        # incident's detail auto-pauses live_mode a few lines down in
        # view_incident_detail(), which stops the periodic timer from ever
        # calling update_queue() again until the analyst acts on it. Without
        # capturing it now, there would be no successful update_queue() call
        # where this incident was both selected and still present in the
        # fetch window to opportunistically cache it during.
        self._selected_incident_cache = inc
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
