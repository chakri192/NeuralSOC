#!/usr/bin/env python3
"""
cli_dashboard.py
================
A Terminal User Interface (TUI) for the Data Diode Cyber Threat Detector.
Subscribes to Redpanda and provides a live SOC dashboard directly in the terminal.
"""

import time
import json
import argparse
from datetime import datetime
from collections import deque

try:
    from kafka import KafkaConsumer
except ImportError:
    from kafka_python_ng import KafkaConsumer

from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.console import Console

console = Console()

class CLIDashboard:
    def __init__(self, broker: str, topic: str):
        self.broker = broker
        self.topic = topic
        # Keep a large history in memory, but only display what fits
        self.alerts = deque(maxlen=1000)
        self.stats = {
            "total": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        self.consumer = self._init_consumer()

    def _init_consumer(self):
        try:
            return KafkaConsumer(
                self.topic,
                bootstrap_servers=self.broker.split(","),
                group_id=f"cli-dashboard-{int(time.time())}",
                auto_offset_reset="latest",
                enable_auto_commit=True,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=500,
            )
        except Exception as e:
            console.print(f"[bold red]Failed to connect to Redpanda Broker at {self.broker}: {e}[/bold red]")
            return None

    def poll_alerts(self):
        if not self.consumer:
            return
        
        try:
            raw_msgs = self.consumer.poll(timeout_ms=500, max_records=50)
            for tp, msgs in raw_msgs.items():
                for msg in msgs:
                    alert = msg.value
                    self.alerts.appendleft(alert)
                    self.stats["total"] += 1
                    sev = alert.get("severity", "LOW").upper()
                    if sev in self.stats:
                        self.stats[sev] += 1
        except Exception:
            pass

    def generate_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
        )
        layout["main"].split_row(
            Layout(name="left_panel", ratio=2),
            Layout(name="right_panel", ratio=1),
        )

        # Header
        header = Panel(
            Text("DATA DIODE CYBER THREAT DETECTOR - LIVE TERMINAL DASHBOARD", justify="center", style="bold white on #1e3a8a"),
            style="white"
        )
        layout["header"].update(header)

        # Alert Table (Left)
        table = Table(show_header=True, header_style="bold #38bdf8", expand=True)
        table.add_column("Time", style="dim", width=12)
        table.add_column("Sev", justify="center", width=8)
        table.add_column("Threat Class", style="cyan")
        table.add_column("Source", style="green")
        table.add_column("Destination", style="#fb7185")
        table.add_column("Conf", justify="right", width=6)

        # Dynamically calculate rows based on terminal height
        term_height = console.size.height
        max_rows = max(5, term_height - 12)  # Adjust for headers, borders, and margins

        for a in list(self.alerts)[:max_rows]:
            sev = a.get("severity", "LOW")
            color = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "blue" if sev == "MEDIUM" else "white"
            ts = a.get("timestamp", "")[11:19]  # Just HH:MM:SS
            conf = f"{int(a.get('confidence_score', 0) * 100)}%"
            table.add_row(
                ts,
                f"[{color}]{sev}[/{color}]",
                a.get("threat_class", ""),
                f"{a.get('src_ip', '')}:{a.get('src_port', '')}",
                f"{a.get('dst_ip', '')}:{a.get('dst_port', '')}",
                conf
            )

        layout["left_panel"].update(Panel(table, title="[bold #38bdf8]Live Alert Feed[/bold #38bdf8]", border_style="#0ea5e9"))

        # KPI Stats (Right)
        stats_text = (
            f"\n[bold white]Total Alerts Evaluated:[/bold white] {self.stats['total']}\n\n"
            f"[bold red]CRITICAL Threats:[/bold red] {self.stats['CRITICAL']}\n"
            f"[bold yellow]HIGH Severity:[/bold yellow]    {self.stats['HIGH']}\n"
            f"[bold blue]MEDIUM Severity:[/bold blue]  {self.stats['MEDIUM']}\n"
            f"[bold white]LOW Info:[/bold white]         {self.stats['LOW']}\n\n"
            "---\n\n"
            "[bold #22c55e]System Status: ONLINE[/bold #22c55e]\n"
            f"[dim]Broker: {self.broker}\nTopic: {self.topic}[/dim]"
        )
        layout["right_panel"].update(Panel(stats_text, title="[bold white]Threat KPIs[/bold white]", border_style="#475569"))

        return layout

    def run(self):
        if not self.consumer:
            return
            
        with Live(self.generate_layout(), refresh_per_second=2, screen=True) as live:
            try:
                while True:
                    self.poll_alerts()
                    live.update(self.generate_layout())
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terminal UI Dashboard for Cyber Threat Detection")
    parser.add_argument("--broker", default="localhost:9092", help="Redpanda broker address")
    parser.add_argument("--topic", default="security_alerts", help="Topic to consume from")
    args = parser.parse_args()

    dashboard = CLIDashboard(args.broker, args.topic)
    dashboard.run()
