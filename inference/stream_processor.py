import os
import sys
import json
import time
import signal
import uuid
from datetime import datetime, timezone
from kafka import KafkaConsumer, KafkaProducer

# Append parent dir for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import ThreatModelOrchestrator
from inference.schemas import validate_alert

from inference.correlation import IncidentCorrelator

BROKERS = os.getenv("REDPANDA_BROKERS", "localhost:9092")

try:
    consumer = KafkaConsumer(
        "raw_traffic",
        bootstrap_servers=[BROKERS],
        group_id="soc-stream-processor",
        auto_offset_reset="latest",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        session_timeout_ms=10000
    )
    producer = KafkaProducer(
        bootstrap_servers=[BROKERS],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )
except Exception as e:
    print(f"[Processor] Connection failed: {e}")
    sys.exit(1)

orchestrator = ThreatModelOrchestrator()
correlator = IncidentCorrelator()
running = True

def handle_sigint(sig, frame):
    global running
    print("\n[Processor] Gracefully shutting down...")
    running = False
    producer.flush()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

def format_alert(event: dict, detection: dict) -> dict:
    """Formats the raw detection into the strict ALERT_SCHEMA."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": f"ALT-{uuid.uuid4().hex[:12]}",
        "flow_id": event.get("uid"),
        "event_type": event.get("event_type", "unknown"),
        "threat_class": detection.get("threat_class"),
        "confidence_score": detection.get("confidence"),
        "severity": detection.get("severity"),
        "mitre_tactic": detection.get("mitre_tactic"),
        "mitre_technique": detection.get("mitre_technique"),
        "source_ip": event.get("id.orig_h", "unknown"),
        "destination_ip": event.get("id.resp_h", "unknown"),
        "evidence": detection.get("evidence", {}),
        "model_name": detection.get("model_name", detection.get("rule_id", "Rule_Engine")),
        "model_version": detection.get("model_version", "1.0"),
        "schema_version": "1.0"
    }

def main():
    print("[Processor] Stream processing engine active. Waiting for events...")
    
    while running:
        raw_msgs = consumer.poll(timeout_ms=1000)
        for tp, msgs in raw_msgs.items():
            for msg in msgs:
                event = msg.value
                
                # 1. Feature Extraction
                features = extract_features(event)
                
                # 2. Detection (Rules & ML)
                detections = []
                detections.extend(evaluate_rules(event, features))
                detections.extend(orchestrator.evaluate(event, features))
                
                # 3. Validation, Alert Publishing, and Correlation
                for det in detections:
                    alert = format_alert(event, det)
                    is_valid, err = validate_alert(alert)
                    
                    if is_valid:
                        producer.send("security_alerts", value=alert)
                        
                        # Phase 4: Correlation
                        incident = correlator.add_alert(alert)
                        if incident:
                            print(f"[Processor] CORRELATION TRIGGERED! Incident {incident['incident_id']} generated.")
                            producer.send("incidents", value=incident)
                    else:
                        print(f"[Processor] Dropped invalid alert schema: {err}")
                        producer.send("dead_letter_events", value={"raw": alert, "error": err})
                        
if __name__ == "__main__":
    main()
