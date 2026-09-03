#!/bin/bash
set -e

echo "=== System Healthcheck ==="
echo "[+] Checking Redpanda Cluster..."
docker exec soc-redpanda rpk cluster health

echo "\n[+] Checking Topic Status..."
docker exec soc-redpanda rpk topic list --brokers localhost:9092

echo "\n[+] Healthcheck Complete."
