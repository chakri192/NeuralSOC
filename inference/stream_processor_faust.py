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
# Right-sized thread allocations matching container resource constraints
cpu_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cpu")  # ML Inference, Feature Extraction
io_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="io")  # Redis Correlation
# Track submitted futures for cancellation on SIGTERM (managed on event loop without synchronous locks)
_submitted_cpu_futures = set()
_submitted_io_futures = set()

backpressure_sem = asyncio.Semaphore(8)
_infer_sem = asyncio.Semaphore(4)


@app.page('/healthz')
async def healthz(web, request):
    return web.json({'status': 'ok'})

@app.agent(raw_traffic_topic, concurrency=16)
async def process_traffic(stream):
    async for event in stream:
        async with backpressure_sem:
            # 1. Feature extraction (pure dictionary operations; avoids threadpool overhead/starvation)
            try:
                features = extract_features(event)
            except Exception as e:
                logger.error(f"Feature extraction failed: {e}")
                continue

            # 2. Rule evaluation
            try:
                detections = evaluate_rules(event, features)
            except Exception as e:
                logger.error(f"Rule Evaluation Error: {e}")
                detections = []

            # 3. Deep-Learning inference (CPU-bound, bounded by semaphore + input guard)
            if event.get("event_type") == "dns":
                query = event.get("query", "")
                # Pre-validate domain length before thread dispatch to prevent slow-poison starvation
                if query and len(query) <= 253:
                    try:
                        async with _infer_sem:
                            infer_future = asyncio.get_running_loop().run_in_executor(
                                cpu_executor, dl_engine.predict, dict(features), query
                            )
                            _submitted_cpu_futures.add(infer_future)
                            try:
                                is_dga, prob, _ = await asyncio.wait_for(infer_future, timeout=5.0)
                            finally:
                                _submitted_cpu_futures.discard(infer_future)
                        if is_dga:
                            detections.append({
                                "threat_class": "DGA / DNS Tunnelling",
                                "severity": "high",
                                "confidence": prob,
                                "rule_id": "DL_CNN_DGA"
                            })
                    except asyncio.TimeoutError:
                        logger.warning("DL inference timed out for domain (len=%d); skipping", len(query))
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

                # Two-Phase Commit safety: publish alert to Kafka FIRST.
                # Only mutate Redis correlation state after the write is durably
                # persisted in the broker.  A Kafka timeout before this point
                # routes to DLQ without touching Redis, preventing phantom
                # incident state that can never be reconciled.
                try:
                    await asyncio.wait_for(alerts_topic.send(value=alert), timeout=3.0)
                except asyncio.TimeoutError:
                    logger.warning("Alert Kafka publish timed out for %s; routing to DLQ (Redis NOT mutated)", alert.get("alert_id"))
                    await _send_dlq_safely(event, alert, "Timeout during alert Kafka publish")
                    continue
                except Exception as kafka_err:
                    logger.error("Alert Kafka publish failed for %s: %s; routing to DLQ (Redis NOT mutated)", alert.get("alert_id"), kafka_err)
                    await _send_dlq_safely(event, alert, f"KafkaPublishError: {kafka_err}")
                    continue

                # Alert is now durably in Kafka — safe to mutate Redis correlation state.
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
                except asyncio.TimeoutError:
                    logger.warning("Correlation/incident send timed out for %s; alert already committed to Kafka", alert.get("alert_id"))
                    await _send_dlq_safely(event, alert, "Timeout during correlation or incident send")
                except redis.RedisError as redis_err:
                    logger.error("Redis correlation failed for alert %s: %s; alert already committed to Kafka", alert.get("alert_id"), redis_err)
                    await _send_dlq_safely(event, alert, f"RedisUnavailable: {redis_err}")
                except Exception as e:
                    logger.error("Processing error during correlation/incident emit: %s", e)
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

import atexit

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

async def _on_before_shutdown(sender=None, **kwargs):
    _shutdown_executors()
    logger.info("Stream processor shutting down: executors cleaned up")

app.on_before_shutdown.connect(_on_before_shutdown)
atexit.register(_shutdown_executors)

if __name__ == "__main__":
    app.main()