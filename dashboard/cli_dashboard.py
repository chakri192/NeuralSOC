#!/usr/bin/env python3
"""
cli_dashboard.py
================
Refined, Enterprise-Grade Terminal UI (TUI) for SOC Analysts.
Uses advanced `rich` layout features to provide a dense, highly readable,
and professional single-pane-of-glass view.

Read-only live monitor: shares its backend (shared/data_access.py), its
login credential (shared/auth.py), and its color palette
(dashboard/theme.py) with the web dashboard and terminal/tsoc_console.py,
but carries no triage actions of its own -- tsoc_console.py's
queue+detail view is where an analyst acknowledges/confirms/dismisses
an incident; this is the wall you glance at.
"""
import os
import re
import secrets
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import Counter

from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from dashboard.theme import PALETTE, SEVERITY_COLORS
from shared.auth import resolve_dashboard_password
from shared.data_access import stream_manager

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\].*?(?:\x07|\x1B\\))')


def sanitize_ansi(text) -> str:
    """Strips raw terminal escape sequences from attacker-influenced
    values (network evidence) before they reach a Rich renderable. A
    different vector than rich.markup.escape() below -- that handles
    literal '[bracket]' markup injection, this handles raw ESC bytes --
    so both are applied, neither replaces the other."""
    if not isinstance(text, str):
        text = str(text)
    return ANSI_ESCAPE.sub('', text)


console = Console()

_SEVERITY_ICONS = {"critical": "[C]", "high": "[H]", "medium": "[M]", "low": "[L]"}


class CLIDashboard:
    def __init__(self):
        self._started_at = time.monotonic()

    def _current_window(self):
        """Recomputes severity/threat counts fresh from stream_manager's
        current alert window on every frame. stream_manager already runs
        its own background poll thread (refreshed every 2s) and is the
        single source of truth every other UI in the product reads from
        -- keeping a second, ever-growing local accumulator here would
        just drift out of sync with what the dashboard/console show."""
        alerts = stream_manager.get_alerts()
        severity_counts = Counter()
        threat_counts = Counter()
        for a in alerts:
            severity_counts[str(a.get("severity", "low")).lower()] += 1
            threat_counts[a.get("threat_class", "Unknown")] += 1
        return alerts, severity_counts, threat_counts

    def generate_layout(self) -> Layout:
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="kpis", size=5),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(name="feed", ratio=2),
            Layout(name="sidebar", ratio=1),
        )
        layout["sidebar"].split_column(
            Layout(name="distribution", ratio=3),
            Layout(name="system", ratio=2),
        )

        alerts, severity_counts, threat_counts = self._current_window()
        healthy = stream_manager.status().get("broker_healthy", False)

        # 1. Header
        header = Panel(
            Text("TACTICAL THREAT INTELLIGENCE (T-SOC)", justify="center", style="bold cyan"),
            style=f"on {PALETTE['surface']}",
        )
        layout["header"].update(header)

        # 2. KPIs
        kpi_table = Table.grid(expand=True)
        for _ in range(4):
            kpi_table.add_column(ratio=1)
        kpi_table.add_row(
            Panel(
                Align.center(Text(f"{len(alerts):,}\nIn Current Window", style="bold blue")),
                border_style=PALETTE["border"],
            ),
            Panel(
                Align.center(Text(f"{severity_counts['critical']:,}\nCritical Threats", style=f"bold {SEVERITY_COLORS['critical']}")),
                border_style=SEVERITY_COLORS["critical"],
            ),
            Panel(
                Align.center(Text(f"{severity_counts['high']:,}\nHigh Severity", style=f"bold {SEVERITY_COLORS['high']}")),
                border_style=SEVERITY_COLORS["high"],
            ),
            Panel(
                Align.center(Text(f"{severity_counts['medium']:,}\nMedium Anomalies", style=f"bold {SEVERITY_COLORS['medium']}")),
                border_style=SEVERITY_COLORS["medium"],
            ),
        )
        layout["kpis"].update(kpi_table)

        # 3. Live Feed Table
        table = Table(show_header=True, header_style=f"bold {PALETTE['text']}", expand=True, border_style=PALETTE["border"])
        table.add_column("Timestamp", style="dim")
        table.add_column("Sev", justify="center")
        table.add_column("Signature / Threat Class", style=PALETTE["text"])
        table.add_column("Source IP", style="green")
        table.add_column("Target IP", style="red")
        table.add_column("Conf", justify="right")

        term_height = console.size.height
        max_rows = max(5, term_height - 20)

        for a in alerts[:max_rows]:
            sev = str(a.get("severity", "low")).lower()
            icon = _SEVERITY_ICONS.get(sev, "[L]")
            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["low"])

            ts_val = a.get("timestamp", "")
            ts = ts_val[11:19] if len(ts_val) > 19 else ts_val

            conf = f"{int(a.get('confidence_score', 0) * 100)}%"
            threat = sanitize_ansi(escape(str(a.get("threat_class", "")).replace("_", " ")))
            s_ip = sanitize_ansi(escape(str(a.get("source_ip", "unknown"))))
            t_ip = sanitize_ansi(escape(str(a.get("destination_ip", "unknown"))))

            table.add_row(
                ts,
                f"[{sev_color}]{icon}[/]",
                threat,
                f"[green]{s_ip}[/]",
                f"[red]{t_ip}[/]",
                conf,
            )

        layout["feed"].update(Panel(table, title=f"[bold {PALETTE['text']}]Real-Time Intrusion Feed[/]", border_style=PALETTE["border"]))

        # 4. Threat Distribution (Sidebar Top)
        dist_table = Table.grid(expand=True)
        dist_table.add_column(ratio=2)
        dist_table.add_column(justify="right")

        max_count = max(threat_counts.values()) if threat_counts else 1
        for threat_name, count in threat_counts.most_common(8):
            clean_name = sanitize_ansi(escape(str(threat_name).replace("_", " ").title()))
            bar_len = int((count / max_count) * 15)
            bar = "█" * bar_len
            dist_table.add_row(f"[{PALETTE['text']}]{clean_name}[/]", f"[{PALETTE['accent']}]{count}[/]")
            dist_table.add_row(f"[dim {PALETTE['accent']}]{bar}[/]", "")

        layout["distribution"].update(Panel(dist_table, title=f"[bold {PALETTE['text']}]Threat Signatures[/]", border_style=PALETTE["border"]))

        # 5. System Status (Sidebar Bottom)
        elapsed = int(time.monotonic() - self._started_at)
        uptime = f"{elapsed // 3600:02d}:{(elapsed % 3600) // 60:02d}:{elapsed % 60:02d}"
        status_text = "[bold green]ONLINE[/]" if healthy else "[bold red]DISCONNECTED[/]"
        backend = sanitize_ansi(escape(str(stream_manager.api_url or "unconfigured")))

        sys_info = (
            f"\n[bold {PALETTE['text']}]Status:[/] {status_text}\n\n"
            f"[dim {PALETTE['text']}]Uptime:[/] {uptime}\n"
            f"[dim {PALETTE['text']}]Backend:[/] {backend}\n\n"
            f"[dim {PALETTE['text']}]Engine:[/] PyTorch DL Hybrid\n"
        )
        layout["system"].update(Panel(sys_info, title=f"[bold {PALETTE['text']}]System Health[/]", border_style=PALETTE["border"]))

        return layout

    def run(self):
        console.clear()
        with Live(self.generate_layout(), refresh_per_second=4, screen=True) as live:
            try:
                while True:
                    time.sleep(0.25)
                    live.update(self.generate_layout())
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Terminating Terminal Dashboard...[/]")


def _login() -> bool:
    """Gates behind the same shared credential as the web dashboard and
    terminal/tsoc_console.py -- one password for the whole product (see
    shared/auth.py)."""
    password = resolve_dashboard_password(warn=True)
    for _ in range(3):
        entered = Prompt.ask("Password", password=True)
        if secrets.compare_digest(entered, password):
            return True
        console.print("[bold red]Incorrect password.[/]")
    return False


if __name__ == "__main__":
    console.print("[bold cyan]T-SOC Terminal Dashboard[/]")
    if not _login():
        console.print("[bold red]Too many failed attempts. Exiting.[/]")
        sys.exit(1)

    stream_manager.start_listeners()
    CLIDashboard().run()
