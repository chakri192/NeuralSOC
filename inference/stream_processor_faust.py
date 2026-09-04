import asyncio
import logging
import signal
import sys
import json
import os
import fcntl
import uuid
import threading
import redis
from datetime import datetime, timezone
from faust import App
from concurrent.futures import ThreadPoolExecutor

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import DeepLearningEngine
from inference.correlation import IncidentCorrelator
from inference.enrichment import ThreatEnricher
from inference.schemas import validate_alert

dl_engine = DeepLearningEngine()
correlator = IncidentCorrelator()
enricher = ThreatEnricher()

logger = logging.getLogger(__name__)
BROKER_URL = os.getenv("REDPANDA_BROKERS", "soc-redpanda-cluster.prod.svc.cluster.local:9092")
app = App('tsoc-stream-processor', broker=f'kafka://{BROKER_URL}')
raw_traffic_topic = app.topic('raw_traffic', value_type=dict)
alerts_topic = app.topic('security_alerts', value_type=dict)
incidents_topic = app.topic("incidents")
dead_letter_topic = app.topic("dead_letter_events", value_type=dict)

# Segregate CPU and I/O ThreadPools to prevent GIL/IO resource starvation
# Right-sized thread allocations matching container resource constraints (1000m CPU)
cpu_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cpu")  # ML Inference, Feature Extraction
io_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="io")  # Redis Correlation
# Track submitted futures for cancellation on SIGTERM (managed on event loop without synchronous locks)
_submitted_cpu_futures = set()
_submitted_io_futures = set()

backpressure_sem = asyncio.Semaphore(8)
_infer_sem = asyncio.Semaphore(2)


@app.page('/healthz')
async def healthz(web, request):
    return web.json({'status': 'ok'})

@app.agent(raw_traffic_topic, concurrency=16)
async def process_traffic(stream):
    async for event in stream:
        async with backpressure_sem:
            # 1. Feature extraction (CPU-bound)
            try:
                # Instead of abandoning the Future via wait_for timeout, use run_in_executor
                # directly since CPU bound operations shouldn't block indefinitely
                # Submit with cancellation tracking; abandon abandoned futures on timeout
                cpu_future = asyncio.get_running_loop().run_in_executor(cpu_executor, extract_features, event)
                _submitted_cpu_futures.add(cpu_future)
                try:
                    features = await asyncio.wait_for(cpu_future, timeout=10.0)
                finally:
                    _submitted_cpu_futures.discard(cpu_future)
            except Exception as e:
                logger.error(f"Feature extraction failed: {e}")
                continue

            # 2. Rule evaluation
            try:
                detections = evaluate_rules(event, features)
            except Exception as e:
                logger.error(f"Rule Evaluation Error: {e}")
                detections = []

            # 3. Deep-Learning inference (CPU-bound)
            if event.get("event_type") == "dns":
                try:
                    async with _infer_sem:
                        infer_future = asyncio.get_running_loop().run_in_executor(
                            cpu_executor, dl_engine.predict, dict(features), event.get("query", "")
                        )
                        _submitted_cpu_futures.add(infer_future)
                        try:
                            is_dga, prob, _ = await asyncio.wait_for(infer_future, timeout=10.0)
                        finally:
                            _submitted_cpu_futures.discard(infer_future)
                    if is_dga:
                        detections.append({
                            "threat_class": "DGA / DNS Tunnelling",
                            "severity": "high",
                            "confidence": prob,
                            "rule_id": "DL_CNN_DGA"
                        })
                except Exception as e:
                    logger.error(f"DL inference failed: {e}")

            # 4. Emit alerts / incidents (IO-bound Redis Correlator)
            for det in detections:
                raw_alert = {
                    "alert_id": f"ALT-{uuid.uuid4().hex[:12]}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": event.get("id.orig_h", "127.0.0.1"),
                    "destination_ip": event.get("id.resp_h", "127.0.0.1"),
                    "threat_class": det.get("threat_class"),
                    "severity": det.get("severity"),
                    "confidence_score": det.get("confidence", 0.9),
                    "evidence": det.get("evidence", {}),
                    "event_type": event.get("event_type", "unknown"),
                    "schema_version": "1.0",
                    "model_name": det.get("rule_id", "Unknown"),
                    "model_version": "1.0",
                    "mitre_tactic": det.get("mitre_tactic"),
                    "mitre_technique": det.get("mitre_technique")
                }

                # Resilient threat intel enrichment
                try:
                    alert = await enricher.enrich(raw_alert)
                except Exception as enrich_err:
                    logger.debug("Enrichment fallback: %s", enrich_err)
                    alert = raw_alert

                # Strict alert schema validation gate
                is_valid, schema_err = validate_alert(alert)
                if not is_valid:
                    logger.warning("Invalid alert schema (%s); routing to DLQ", schema_err)
                    await _send_dlq_safely(event, alert, f"SchemaValidationError: {schema_err}")
                    continue

                try:
                    io_future = asyncio.get_running_loop().run_in_executor(
                        io_executor, correlator.add_alert, alert
                    )
                    _submitted_io_futures.add(io_future)
                    try:
                        incident = await asyncio.wait_for(io_future, timeout=5.0)
                    finally:
                        _submitted_io_futures.discard(io_future)
                    if incident:
                        await asyncio.wait_for(incidents_topic.send(value=incident), timeout=3.0)
                    await asyncio.wait_for(alerts_topic.send(value=alert), timeout=3.0)
                except asyncio.TimeoutError:
                    logger.warning("Correlation/alert send timed out for %s; routing to DLQ", alert.get("alert_id"))
                    await _send_dlq_safely(event, alert, "Timeout during correlation or alert send")
                except redis.RedisError as redis_err:
                    logger.error("Redis correlation failed for alert %s: %s", alert.get("alert_id"), redis_err)
                    await _send_dlq_safely(event, alert, f"RedisUnavailable: {redis_err}")
                except Exception as e:
                    logger.error("Processing error during emit: %s", e)
                    await _send_dlq_safely(event, alert, str(e))

async def _send_dlq_safely(event, alert, error_str):
    try:
        await asyncio.wait_for(dead_letter_topic.send(value={
            "original_event": event,
            "alert": alert,
            "error": error_str
        }), timeout=2.0)
    except Exception as dlq_err:
        logger.error("DLQ send failed (non-blocking): %s", dlq_err)

def _shutdown_executors():
    for f in list(_submitted_cpu_futures):
        f.cancel()
    for f in list(_submitted_io_futures):
        f.cancel()
    for ex in (cpu_executor, io_executor):
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)

@app.on_stop
async def _on_stop():
    _shutdown_executors()
    logger.info("Stream processor shutting down: executors cleaned up")

if __name__ == "__main__":
    app.main()