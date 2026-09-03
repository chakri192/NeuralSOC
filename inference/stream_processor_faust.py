from concurrent.futures import ThreadPoolExecutor
import logging
from pythonjsonlogger import jsonlogger
import sys
import os
import json
import uuid
from datetime import datetime, timezone
import asyncio
import faust

# Assume the repo is installed as a package, but keep path hack just in case

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import ThreatModelOrchestrator
from inference.schemas import validate_alert
from inference.correlation import IncidentCorrelator
from inference.enrichment import ThreatEnricher

# ----------------------------------------------------------------------
# 1. Structured logger (JSON)
# ----------------------------------------------------------------------
logger = logging.getLogger("stream_processor")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Keep the same logger for Faust-related messages
faust_logger = logging.getLogger("faust")
faust_logger.handlers = logger.handlers
faust_logger.setLevel(logging.INFO)

# ----------------------------------------------------------------------
# 2. Faust application definition
# ----------------------------------------------------------------------
BROKERS = os.getenv("REDPANDA_BROKERS", "127.0.0.1:9092")

# ----------------------------------------------------------------------
# Thread Pool
# ----------------------------------------------------------------------
import torch
torch.set_num_threads(1)
CPU_COUNT = min(2, max(1, os.cpu_count() or 1))
import urllib.request
executor = ThreadPoolExecutor(max_workers=CPU_COUNT)

app = faust.App(
    'soc-stream-processor-cluster',
    broker=f'kafka://{BROKERS}',
    value_serializer='json'
)

raw_traffic_topic = app.topic('raw_traffic')
security_alerts_topic = app.topic('security_alerts')
incidents_topic = app.topic('incidents')
dlq_topic = app.topic('dead_letter_events')

# ----------------------------------------------------------------------
# 3. Graceful shutdown task
# ----------------------------------------------------------------------
@app.task
async def on_stop():
    logger.info("SIGTERM received - stopping Faust app and flushing buffers")
    await app.stop()
    try:
        app.correlator.redis.connection_pool.disconnect()
    except Exception:
        pass

# ----------------------------------------------------------------------
# 4. Instantiate heavy objects once per Faust worker
# ----------------------------------------------------------------------
@app.signal(app.signals.startup)
async def init_components(app, **kw):
    app.orchestrator = ThreatModelOrchestrator()
    app.correlator = IncidentCorrelator()
    app.enricher = ThreatEnricher()

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

# ----------------------------------------------------------------------
# 5. Agent Processing Loop
# ----------------------------------------------------------------------
@app.agent(raw_traffic_topic, concurrency=2, max_incoming=100)
async def process_traffic(stream):
    async for event in stream:
        try:
            # 1. Feature extraction in a thread to avoid blocking event loop
            features = await asyncio.get_running_loop().run_in_executor(executor, extract_features, event)
            
            # 2. Run rule engine and ML model concurrently with timeouts to prevent stalling
            rule_task = asyncio.get_running_loop().run_in_executor(executor, evaluate_rules, event, features)
            ml_task   = asyncio.get_running_loop().run_in_executor(executor, app.orchestrator.evaluate, event, features)
            rule_res, ml_res = await asyncio.wait_for(asyncio.gather(rule_task, ml_task), timeout=5.0)
            
            detections = []
            detections.extend(rule_res)
            detections.extend(ml_res)
            
            # 3. Process each detection
            for det in detections:
                alert = format_alert(event, det)
                is_valid, err = validate_alert(alert)
                
                if is_valid:
                    alert = await app.enricher.enrich(alert)
                    send_fut = await security_alerts_topic.send(value=alert)
                    await send_fut
                    
                    # Correlation in a thread
                    incident = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(executor, app.correlator.add_alert, alert), timeout=3.0)
                    if incident:
                        inc_fut = await incidents_topic.send(value=incident)
                        await inc_fut
                else:
                    logger.error(f"[Faust] Dropped invalid alert schema: {err}")
        except Exception as e:
            logger.exception("[DLQ] Pipeline crash prevented. Routing to dead-letter")
            safe_event = {k: v for k, v in event.items() if k not in {"id.orig_h", "id.resp_h", "uid", "payload"}}
            await dlq_topic.send(value={"raw_event": safe_event, "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()})

if __name__ == '__main__':
    app.main()
