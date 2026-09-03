import os
import sys
import json
import time
import signal
import argparse
import subprocess
import threading
from kafka import KafkaProducer

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from inference.schemas import validate_zeek_event

BROKERS = os.getenv("REDPANDA_BROKERS", "localhost:9092")
SENSOR_ID = os.getenv("SENSOR_ID", "sensor-01")

try:
    producer = KafkaProducer(
        bootstrap_servers=[BROKERS],
        value_serializer=lambda v: json.dumps(v).encode('utf-8') if isinstance(v, dict) else str(v).encode('utf-8'),
        retries=5,
        acks='all',
        max_request_size=5242880 # 5MB limit
    )
except Exception as e:
    print(f"[Tailer] Failed to connect to Redpanda: {e}")
    sys.exit(1)

metrics = {"read": 0, "published": 0, "rejected": 0, "dead_lettered": 0}
running = True

def handle_sigint(sig, frame):
    global running
    print(f"\n[Tailer] Shutting down gracefully... Final Metrics: {metrics}")
    running = False
    producer.flush(timeout=5)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

def process_log(file_path, log_type):
    global metrics
    print(f"[Tailer] Tailing {file_path} as type '{log_type}'...")
    
    # Touch file if it doesn't exist so tail doesn't fail
    if not os.path.exists(file_path):
        open(file_path, 'a').close()

    try:
        proc = subprocess.Popen(['tail', '-F', file_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        while running:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            metrics["read"] += 1
            line = line.strip()
            if not line:
                continue
            
            try:
                event = json.loads(line)
                
                # Strict Schema Validation Constraint
                if not validate_zeek_event(event):
                    raise ValueError("Missing required Zeek fields (ts)")
                    
                # Enrichment
                event["ingestion_timestamp"] = time.time()
                event["sensor_id"] = SENSOR_ID
                event["event_type"] = log_type
                
                producer.send("raw_traffic", value=event)
                metrics["published"] += 1
                
            except (json.JSONDecodeError, ValueError) as e:
                metrics["rejected"] += 1
                # Dead letter queue routing Constraint
                dl_event = {
                    "raw_payload": line,
                    "error": str(e),
                    "sensor_id": SENSOR_ID,
                    "timestamp": time.time()
                }
                producer.send("dead_letter_events", value=dl_event)
                metrics["dead_lettered"] += 1
                
    except Exception as e:
        print(f"[Tailer] Error tailing {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs-dir", default="data/zeek_logs", help="Directory containing Zeek logs")
    args = parser.parse_args()
    
    os.makedirs(args.logs_dir, exist_ok=True)
    
    # Standard Zeek files to monitor
    log_targets = {
        "conn": os.path.join(args.logs_dir, "conn.log"),
        "dns": os.path.join(args.logs_dir, "dns.log"),
        "ssl": os.path.join(args.logs_dir, "ssl.log")
    }
    
    threads = []
    for log_type, path in log_targets.items():
        t = threading.Thread(target=process_log, args=(path, log_type), daemon=True)
        t.start()
        threads.append(t)
        
    print("[Tailer] Started safely. Press Ctrl+C to exit.")
    while running:
        time.sleep(1)

if __name__ == "__main__":
    main()
