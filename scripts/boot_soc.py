#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import threading
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel

console = Console()

def find_docker():
    paths = [
        "/Applications/Docker.app/Contents/Resources/bin/docker",
        "/Applications/Docker 2.app/Contents/Resources/bin/docker",
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker"
    ]
    try:
        if subprocess.run(["docker", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return "docker"
    except FileNotFoundError:
        pass
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def main():
    console.clear()
    console.print(Panel.fit("[bold cyan]AI Cyber Threat Detection Enclave[/bold cyan]\n[dim]Initialization Sequence Initiated...[/dim]", border_style="cyan"))
    
    docker_bin = find_docker()
    if not docker_bin:
        console.print("[bold red]❌ Error:[/bold red] Docker binary not found. Please ensure Docker Desktop is installed.")
        sys.exit(1)
        
    # CRITICAL FIX: macOS 'docker-credential-desktop' often fails if PATH isn't correctly set to the Docker.app bin folder
    os.environ["PATH"] += os.pathsep + os.path.dirname(docker_bin)

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="green", finished_style="bold green"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        # 1. Redpanda Boot
        task1 = progress.add_task("[cyan]Booting Message Broker (Redpanda)...", total=100)
        subprocess.run([docker_bin, "compose", "up", "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for i in range(100):
            time.sleep(0.05)
            progress.update(task1, advance=1)
            
        # 2. AI Engines
        task2 = progress.add_task("[cyan]Loading Neural Networks & Stream Processor...", total=100)
        subprocess.Popen(["venv/bin/python3", "scripts/simulate_zeek_feed.py", "--rate", "15.0", "--burst-attacks"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["venv/bin/python3", "ingest/tail_to_redpanda.py", "--broker", "localhost:9092", "--log-dir", "data/zeek_logs"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["venv/bin/python3", "inference/stream_processor.py", "--broker", "localhost:9092"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        for i in range(100):
            time.sleep(0.03)
            progress.update(task2, advance=1)
            
        # 3. Tunneling
        task3 = progress.add_task("[cyan]Establishing Secure Cloudflare Tunnel...", total=100)
        os.system("cloudflared tunnel --url http://localhost:8501 > /tmp/cf.log 2>&1 &")
        for i in range(100):
            time.sleep(0.02)
            progress.update(task3, advance=1)
            
        # 4. Web UI
        task4 = progress.add_task("[cyan]Launching Web Dashboard...", total=100)
        subprocess.Popen(["venv/bin/streamlit", "run", "dashboard/app.py", "--server.headless=true", "--server.port=8501"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for i in range(100):
            time.sleep(0.02)
            progress.update(task4, advance=1)

    time.sleep(2)
    # Extract Cloudflare URL
    cf_url = "Waiting for tunnel..."
    try:
        # We sleep a bit extra just to ensure Cloudflare has time to print the final URL to the log
        time.sleep(3)
        out = subprocess.check_output("grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' /tmp/cf.log | head -1", shell=True, text=True).strip()
        if out:
            cf_url = out
    except Exception:
        cf_url = "http://localhost:8501 (Local Only - Tunnel Failed)"

    console.print("\n[bold green]✅ System Online.[/bold green]")
    console.print(Panel(
        f"[bold white]Local Network:[/bold white] http://localhost:8501\n"
        f"[bold white]Public Secure Tunnel:[/bold white] [cyan underline]{cf_url}[/cyan underline]\n\n"
        "[dim]Press Ctrl+C to terminate services.[/dim]",
        title="[bold green]Access Points[/bold green]",
        border_style="green"
    ))

if __name__ == "__main__":
    try:
        main()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Shutting down Enclave...[/bold yellow]")
        os.system("pkill -f 'simulate_zeek_feed|tail_to_redpanda|stream_processor|streamlit|cloudflared'")
        docker_bin = find_docker()
        if docker_bin:
            os.system(f"\"{docker_bin}\" compose down >/dev/null 2>&1")
        sys.exit(0)
