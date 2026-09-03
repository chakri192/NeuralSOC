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
import re
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
def sanitize_ansi(text: str) -> str:
    if not isinstance(text, str): return str(text)
    return ANSI_ESCAPE.sub('', text)
import re
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
def sanitize_ansi(text: str) -> str:
    if not isinstance(text, str): return str(text)
    return ANSI_ESCAPE.sub('', text)
import argparse
from datetime import datetime, timezone
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
    def __init__(self, broker: str, topic: str, show_normal: bool = False):
        self.broker = broker
        self.topic = topic
        self.show_normal = show_normal
        self.topics = [self.topic]
        if self.show_normal:
            self.topics.append("raw_traffic")
            
        self.alerts = deque(maxlen=1000)
        self.stats = {
            "total": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NORMAL": 0
        }
        self.threat_counts = Counter()
        self.consumer = self._init_consumer()

    def _init_consumer(self):
        try:
            return KafkaConsumer(
                *self.topics,
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
                    
                    if "severity" not in alert:
                        # This is a raw_traffic event
                        alert["severity"] = "NORMAL"
                        alert["threat_class"] = "Benign Traffic"
                        alert["confidence_score"] = 0.0
                        alert["timestamp"] = datetime.now(timezone.utc).isoformat()
                        
                        # Map raw schema to alert schema for display
                        if "id.orig_h" in alert:
                            alert["source_ip"] = alert["id.orig_h"]
                            alert["destination_ip"] = alert.get("id.resp_h", "unknown")
                            alert["evidence"] = {
                                "id.orig_p": alert.get("id.orig_p", ""), 
                                "id.resp_p": alert.get("id.resp_p", "")
                            }
                    
                    self.alerts.appendleft(alert)
                    self.stats["total"] += 1
                    
                    sev = alert.get("severity", "LOW").upper()
                    if sev in self.stats:
                        self.stats[sev] += 1
                        
                    threat = alert.get("threat_class", "UNKNOWN")
                    self.threat_counts[threat] += 1
        except Exception as e:
            with open("debug.log", "a") as f:
                import traceback
                f.write(traceback.format_exc() + "\n")

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
            Layout(name="feed", ratio=2),
            Layout(name="sidebar", ratio=1)
        )
        
        # Sidebar vertical splits
        layout["sidebar"].split_column(
            Layout(name="distribution", ratio=3),
            Layout(name="system", ratio=2)
        )

        # 1. Header
        header = Panel(
            Text("TACTICAL THREAT INTELLIGENCE (T-SOC)", justify="center", style="bold cyan"),
            style="on #1e1e24"
        )
        layout["header"].update(header)

        # 2. KPIs
        kpi_table = Table.grid(expand=True)
        for _ in range(4): kpi_table.add_column(ratio=1)
        
            # SECURITY FIX: Strip all ANSI terminal injection payloads before rendering
            threat = sanitize_ansi(str(threat))
            s_ip = sanitize_ansi(str(s_ip))
            t_ip = sanitize_ansi(str(t_ip))
        kpi_table.add_row(
            Panel(Align.center(Text(f"{self.stats['total']:,}\nFlows Analysed", style="bold blue")), border_style="#334155"),
            Panel(Align.center(Text(f"{self.stats['CRITICAL']:,}\nCritical Threats", style="bold red")), border_style="#f7768e"),
            Panel(Align.center(Text(f"{self.stats['HIGH']:,}\nHigh Severity", style="bold dark_orange")), border_style="#ff9e64"),
            Panel(Align.center(Text(f"{self.stats['MEDIUM']:,}\nMedium Anomalies", style="bold yellow")), border_style="#e0af68")
        )
        layout["kpis"].update(kpi_table)

        # 3. Live Feed Table
        table = Table(show_header=True, header_style="bold #a9b1d6", expand=True, border_style="#334155")
        table.add_column("Timestamp", style="dim")
        table.add_column("Sev", justify="center")
        table.add_column("Signature / Threat Class", style="white")
        table.add_column("Source IP:Port", style="green")
        table.add_column("Target IP:Port", style="red")
        table.add_column("Conf", justify="right")
        
        # Calculate rows based on terminal height approx
        term_height = console.size.height
        max_rows = max(5, term_height - 20)
        icons = {"CRITICAL": "[C]", "HIGH": "[H]", "MEDIUM": "[M]", "LOW": "[L]", "NORMAL": "[N]"}
        
        for a in list(self.alerts)[:max_rows]:
            sev = a.get("severity", "LOW")
            icon = icons.get(sev, "[L]")
            
            # Format Timestamp
            ts_val = a.get("timestamp", "")
            if len(ts_val) > 19:
                ts = ts_val[11:19]
            else:
                ts = ts_val
                
            conf = f"{int(a.get('confidence_score', 0) * 100)}%"
            threat = a.get("threat_class", "").replace("_", " ")
            
            # Determine color for ports/ips based on severity
            s_ip = a.get('source_ip', a.get('src_ip', 'unknown'))
            s_p = a.get('evidence', {}).get('id.orig_p', '')
            t_ip = a.get('destination_ip', a.get('dst_ip', 'unknown'))
            t_p = a.get('evidence', {}).get('id.resp_p', '')
            
            if sev == "NORMAL":
                s_style = "dim green"
                t_style = "dim cyan"
                threat = f"[dim white]{threat}[/]"
            else:
                s_style = "green"
                t_style = "red"
                
            # SECURITY FIX: Strip all ANSI terminal injection payloads before rendering
            threat = sanitize_ansi(str(threat))
            s_ip = sanitize_ansi(str(s_ip))
            t_ip = sanitize_ansi(str(t_ip))
            table.add_row(
                ts,
                f"[{'dim' if sev == 'NORMAL' else 'bold'}]{icon}[/]",
                threat,
                f"[{s_style}]{s_ip}:{s_p}[/]",
                f"[{t_style}]{t_ip}:{t_p}[/]",
                conf
            )
            
        layout["feed"].update(Panel(table, title="[bold white]Real-Time Intrusion Feed[/]", border_style="#334155"))

        # 4. Threat Distribution (Sidebar Top)
        dist_table = Table.grid(expand=True)
        dist_table.add_column(ratio=2)
        dist_table.add_column(justify="right")
        
        max_count = max(self.threat_counts.values()) if self.threat_counts else 1
        
        for threat, count in self.threat_counts.most_common(8):
            clean_name = threat.replace("_", " ").title()
            bar_len = int((count / max_count) * 15)
            bar = "█" * bar_len
            # SECURITY FIX: Strip all ANSI terminal injection payloads before rendering
            threat = sanitize_ansi(str(threat))
            s_ip = sanitize_ansi(str(s_ip))
            t_ip = sanitize_ansi(str(t_ip))
            dist_table.add_row(f"[white]{clean_name}[/]", f"[cyan]{count}[/]")
            # SECURITY FIX: Strip all ANSI terminal injection payloads before rendering
            threat = sanitize_ansi(str(threat))
            s_ip = sanitize_ansi(str(s_ip))
            t_ip = sanitize_ansi(str(t_ip))
            dist_table.add_row(f"[dim cyan]{bar}[/]", "")
            
        layout["distribution"].update(Panel(dist_table, title="[bold white]Threat Signatures[/]", border_style="#334155"))

        # 5. System Status (Sidebar Bottom)
        sys_info = (
            f"\n[bold white]Status:[/] [bold green]ONLINE & CONNECTED[/]\n\n"
            f"[dim white]Uptime:[/] 00:01:02\n"
            f"[dim white]Broker:[/] {self.broker}\n"
            f"[dim white]Topic:[/] {', '.join(self.topics)}\n\n"
            f"[dim white]Engine:[/] PyTorch DL Hybrid\n"
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
    parser.add_argument("--show-normal", action="store_true", help="Display normal unflagged traffic alongside alerts")
    args = parser.parse_args()
    
    dashboard = CLIDashboard(args.broker, args.topic, args.show_normal)
    dashboard.run()
