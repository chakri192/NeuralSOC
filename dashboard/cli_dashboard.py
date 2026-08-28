#!/usr/bin/env python3
"""
cli_dashboard.py
================
Refined, Enterprise-Grade Terminal UI (TUI) for SOC Analysts.
Uses advanced `rich` layout features to provide a dense, highly readable,
and professional single-pane-of-glass view.
"""

import time
import json
import argparse
from datetime import datetime
from collections import deque, Counter

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
from rich.align import Align
from rich.progress_bar import ProgressBar

console = Console()

class CLIDashboard:
    def __init__(self, broker: str, topic: str):
        self.broker = broker
        self.topic = topic
        self.alerts = deque(maxlen=1000)
        self.stats = {
            "total": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        self.threat_counts = Counter()
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
            # We don't crash, we just show offline status
            return None

    def poll_alerts(self):
        if not self.consumer:
            # Attempt reconnect periodically if offline
            if int(time.time()) % 5 == 0:
                self.consumer = self._init_consumer()
            return
        
        try:
            raw_msgs = self.consumer.poll(timeout_ms=500, max_records=100)
            for tp, msgs in raw_msgs.items():
                for msg in msgs:
                    alert = msg.value
                    self.alerts.appendleft(alert)
                    self.stats["total"] += 1
                    
                    sev = alert.get("severity", "LOW").upper()
                    if sev in self.stats:
                        self.stats[sev] += 1
                        
                    threat = alert.get("threat_class", "UNKNOWN")
                    self.threat_counts[threat] += 1
        except Exception:
            pass

    def generate_layout(self) -> Layout:
        layout = Layout()
        
        # Main vertical splits
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="kpis", size=5),
            Layout(name="body")
        )
        
        # Body horizontal splits
        layout["body"].split_row(
            Layout(name="feed", ratio=7),
            Layout(name="sidebar", ratio=3)
        )
        
        # Sidebar vertical splits
        layout["sidebar"].split_column(
            Layout(name="distribution", ratio=6),
            Layout(name="system", ratio=4)
        )

        # 1. Header
        header_text = Text("TACTICAL THREAT INTELLIGENCE (T-SOC)", justify="center", style="bold white")
        header = Panel(header_text, style="on #0f172a", border_style="#334155")
        layout["header"].update(header)

        # 2. KPIs (Horizontal Grid)
        kpi_layout = Layout()
        kpi_layout.split_row(
            Layout(Panel(Align.center(Text(f"{self.stats['total']:,}\nFlows Analysed", justify="center", style="bold blue")), border_style="blue")),
            Layout(Panel(Align.center(Text(f"{self.stats['CRITICAL']:,}\nCritical Threats", justify="center", style="bold red")), border_style="red")),
            Layout(Panel(Align.center(Text(f"{self.stats['HIGH']:,}\nHigh Severity", justify="center", style="bold dark_orange")), border_style="dark_orange")),
            Layout(Panel(Align.center(Text(f"{self.stats['MEDIUM']:,}\nMedium Anomalies", justify="center", style="bold yellow")), border_style="yellow"))
        )
        layout["kpis"].update(kpi_layout)

        # 3. Alert Feed Table
        table = Table(show_header=True, header_style="bold #94a3b8", expand=True, border_style="#334155", row_styles=["", "dim"])
        table.add_column("Timestamp", style="#64748b", width=12)
        table.add_column("Sev", justify="center", width=5)
        table.add_column("Signature / Threat Class", style="bold white")
        table.add_column("Source IP:Port", style="#22c55e")
        table.add_column("Target IP:Port", style="#ef4444")
        table.add_column("Conf", justify="right", width=5)

        term_height = console.size.height
        max_rows = max(5, term_height - 18)  # Account for headers, kpis, borders

        icons = {"CRITICAL": "[C]", "HIGH": "[H]", "MEDIUM": "[M]", "LOW": "[L]"}
        
        for a in list(self.alerts)[:max_rows]:
            sev = a.get("severity", "LOW")
            icon = icons.get(sev, "[L]")
            ts = a.get("timestamp", "00:00:00T00")[11:19]
            conf = f"{int(a.get('confidence_score', 0) * 100)}%"
            threat = a.get("threat_class", "").replace("_", " ")
            
            table.add_row(
                ts,
                icon,
                threat,
                f"{a.get('src_ip', '')}:{a.get('src_port', '')}",
                f"{a.get('dst_ip', '')}:{a.get('dst_port', '')}",
                conf
            )
            
        layout["feed"].update(Panel(table, title="[bold white]Real-Time Intrusion Feed[/]", border_style="#334155"))

        # 4. Threat Distribution (Sidebar Top)
        dist_table = Table.grid(padding=(0, 2), expand=True)
        dist_table.add_column(justify="left", ratio=1)
        dist_table.add_column(justify="right")
        
        max_count = max(self.threat_counts.values()) if self.threat_counts else 1
        
        for threat, count in self.threat_counts.most_common(8):
            clean_name = threat.replace("_", " ").title()
            bar_len = int((count / max_count) * 15)
            bar = "█" * bar_len
            dist_table.add_row(f"[white]{clean_name}[/]", f"[cyan]{count}[/]")
            dist_table.add_row(f"[dim cyan]{bar}[/]", "")
            dist_table.add_row("", "") # spacing
            
        layout["distribution"].update(Panel(dist_table, title="[bold white]Threat Signatures[/]", border_style="#334155"))

        # 5. System Status (Sidebar Bottom)
        status_color = "bold green" if self.consumer else "bold red"
        status_text = "ONLINE & CONNECTED" if self.consumer else "OFFLINE (AWAITING BROKER)"
        
        uptime = time.strftime('%H:%M:%S', time.gmtime(time.time() - getattr(self, 'start_time', time.time())))
        if not hasattr(self, 'start_time'):
            self.start_time = time.time()
            
        sys_info = (
            f"\nStatus: [{status_color}]{status_text}[/]\n\n"
            f"[dim]Uptime:[/dim] [white]{uptime}[/white]\n"
            f"[dim]Broker:[/dim] [white]{self.broker}[/white]\n"
            f"[dim]Topic:[/dim]  [white]{self.topic}[/white]\n\n"
            f"[dim]Engine:[/dim] PyTorch DL Hybrid"
        )
        layout["system"].update(Panel(sys_info, title="[bold white]System Health[/]", border_style="#334155"))

        return layout

    def run(self):
        console.clear()
        with Live(self.generate_layout(), refresh_per_second=4, screen=True) as live:
            try:
                while True:
                    self.poll_alerts()
                    live.update(self.generate_layout())
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Terminating Terminal Dashboard...[/]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terminal UI Dashboard for Cyber Threat Detection")
    parser.add_argument("--broker", default="localhost:9092", help="Redpanda broker address")
    parser.add_argument("--topic", default="security_alerts", help="Topic to consume from")
    args = parser.parse_args()
    
    dashboard = CLIDashboard(args.broker, args.topic)
    dashboard.run()
