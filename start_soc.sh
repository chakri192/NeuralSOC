#!/bin/bash

# ==============================================================
# AI-Powered Data Diode Threat Detector - Startup Script
# ==============================================================

echo "🚀 Booting AI Cyber Threat Enclave..."

# 1. Start Docker Containers (Redpanda/Kafka)
echo "📦 Starting Message Broker (Redpanda)..."
docker compose up -d

echo "⏳ Waiting for broker to initialize..."
sleep 5

# 2. Start the AI Pipeline & Simulators in the background
echo "🧠 Starting Deep Learning Engine & Data Ingestion..."
venv/bin/python3 scripts/simulate_zeek_feed.py --rate 15.0 &
venv/bin/python3 ingest/tail_to_redpanda.py --broker localhost:9092 --log-dir data/zeek_logs &
venv/bin/python3 inference/stream_processor.py --broker localhost:9092 &

# 3. Start Cloudflare Tunnel
echo "🌍 Starting Cloudflare Public Tunnel..."
cloudflared tunnel --url http://localhost:8501 > /tmp/cloudflare_tunnel.log 2>&1 &

echo "✅ All backend services are running!"
echo "----------------------------------------------------"
echo "🌐 Your local dashboard is at: http://localhost:8501"
echo "To get your public Cloudflare link, open a new terminal and run: grep trycloudflare /tmp/cloudflare_tunnel.log"
echo "----------------------------------------------------"

# 4. Start the Web UI (Foreground)
venv/bin/streamlit run dashboard/app.py --server.headless=true --server.port=8501
