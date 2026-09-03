#!/bin/bash
set -e

echo "Checking Redpanda Cluster Health..."
docker exec soc-redpanda rpk cluster health

echo "Creating Redpanda topics with strict retention policies..."

# Raw traffic: 1 hour retention, 3 partitions for high throughput
docker exec soc-redpanda rpk topic create raw_traffic -p 3 -c retention.ms=3600000 --brokers localhost:9092 || echo "Topic raw_traffic may already exist."

# Alerts: 24 hours retention
docker exec soc-redpanda rpk topic create security_alerts -p 1 -c retention.ms=86400000 --brokers localhost:9092 || echo "Topic security_alerts may already exist."

# Incidents: 7 days retention
docker exec soc-redpanda rpk topic create incidents -p 1 -c retention.ms=604800000 --brokers localhost:9092 || echo "Topic incidents may already exist."

# Dead Letter Events: 24 hours retention for debugging malformed payloads
docker exec soc-redpanda rpk topic create dead_letter_events -p 1 -c retention.ms=86400000 --brokers localhost:9092 || echo "Topic dead_letter_events may already exist."

# System Metrics: 1 hour retention
docker exec soc-redpanda rpk topic create system_metrics -p 1 -c retention.ms=3600000 --brokers localhost:9092 || echo "Topic system_metrics may already exist."

echo "Topics created successfully. Current Topic List:"
docker exec soc-redpanda rpk topic list --brokers localhost:9092
