import asyncio
import logging
import signal
import sys
import json
import os
import fcntl
import uuid
from datetime import datetime, timezone
from faust import App
from concurrent.futures import ThreadPoolExecutor

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import DeepLearningEngine
from inference.correlation import IncidentCorrelator

dl_engine = DeepLearningEngine()
correlator = IncidentCorrelator()

logger = logging.getLogger(__name__)
app = App('tsoc-stream-processor', broker='kafka://soc-redpanda-cluster:9092')
raw_traffic_topic = app.topic('raw_traffic', value_type=dict)
alerts_topic = app.topic('security_alerts', value_type=dict)
incidents_topic = app.topic("incidents")
executor = ThreadPoolExecutor(max_workers=8)
backpressure_sem = asyncio.Semaphore(100)
_infer_sem = asyncio.Semaphore(2)



@app.page('/healthz')
async def healthz(web, request):
    return web.json({'status': 'ok'})

@app.agent(raw_traffic_topic, concurrency=16)
async def process_traffic(stream):
    async for event in stream:
        async with backpressure_sem:
            # 1. Feature extraction
            try:
                features = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(executor, extract_features, event), timeout=5)
            except Exception as e:
                logger.error(f"Feature extraction failed: {e}")
                continue

            # 2. Rule evaluation
            detections = evaluate_rules(event, features)

            # 3. Deep-Learning inference
            try:
                if event.get("event_type") == "dns":
                    async with _infer_sem:
                        is_dga, prob, _ = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(
                            executor, dl_engine.predict, features, event.get("query", "")
                        ), timeout=5)
                    if is_dga:
                        detections.append({
                            "threat_class": "DGA / DNS Tunnelling",
                            "severity": "high",
                            "confidence": prob,
                            "rule_id": "DL_CNN_DGA"
                        })
            except Exception as e:
                logger.error(f"DL inference failed: {e}")

            # 4. Emit alerts / incidents
            try:
                for det in detections:
                    alert = {
                        "alert_id": f"ALT-{uuid.uuid4().hex[:12]}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source_ip": event.get("id.orig_h", "0.0.0.0"),
                        "destination_ip": event.get("id.resp_h", "0.0.0.0"),
                        "threat_class": det.get("threat_class"),
                        "severity": det.get("severity"),
                        "confidence_score": det.get("confidence", 0.9),
                        "evidence": json.dumps(det.get("evidence", {}))
                    }
                    incident = await asyncio.get_running_loop().run_in_executor(executor, correlator.add_alert, alert)
                    if incident:
                        await incidents_topic.send(value=incident)
                    await alerts_topic.send(value=alert)
            except Exception as e:
                logger.error(f"Processing error: {e}")

@app.task
async def on_stop():
    executor.shutdown(wait=False)