import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("faust")
import os
import sys
import json
import uuid
from datetime import datetime, timezone
import faust

# Append parent dir for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import ThreatModelOrchestrator
from inference.schemas import validate_alert
from inference.correlation import IncidentCorrelator
from inference.enrichment import ThreatEnricher

BROKERS = os.getenv("REDPANDA_BROKERS", "127.0.0.1:9092")

app = faust.App(
    'soc-stream-processor-cluster',
    broker=f'kafka://{BROKERS}',
    value_serializer='json',
    store='memory://'
)

raw_traffic_topic = app.topic('raw_traffic')
security_alerts_topic = app.topic('security_alerts')
incidents_topic = app.topic('incidents')
dlq_topic = app.topic('dead_letter_events')

orchestrator = ThreatModelOrchestrator()
correlator = IncidentCorrelator()
enricher = ThreatEnricher()

def format_alert(event: dict, detection: dict) -> dict:
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

@app.agent(raw_traffic_topic)
async def process_traffic(stream):
    async for event in stream:
        try:
            # 1. Feature Extraction
            features = extract_features(event)
        
            # 2. Detection Engine
            detections = []
            detections.extend(evaluate_rules(event, features))
            detections.extend(orchestrator.evaluate(event, features))
        
            # 3. Publish Alerts
            for det in detections:
                alert = format_alert(event, det)
                is_valid, err = validate_alert(alert)
            
                if is_valid:
                    alert = enricher.enrich(alert)
                    await security_alerts_topic.send(value=alert)
                
                    # 4. Correlate Incidents
                    incident = correlator.add_alert(alert)
                    if incident:
                        await incidents_topic.send(value=incident)
                else:
                    logger.error(f"[Faust] Dropped invalid alert schema: {err}")
        except Exception as e:
            logger.error(f"[DLQ] Pipeline crash prevented. Routing bad event to DLQ. Error: {str(e)}")
            await dlq_topic.send(value={"raw_event": event, "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()})

if __name__ == '__main__':
    app.main()
