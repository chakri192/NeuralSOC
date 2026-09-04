import jsonschema
import logging
import json
import os
import time
import uuid
import fcntl
import threading
from kafka import KafkaConsumer, KafkaProducer
from kafka.structs import OffsetAndMetadata, TopicPartition
from api.database import SessionLocal, engine, Base
from api.models import Alert

logger = logging.getLogger(__name__)

brokers = os.getenv("REDPANDA_BROKERS", "soc-redpanda-cluster.prod.svc.cluster.local:9092")
topic = os.getenv("ALERTS_TOPIC", "security_alerts")
DLQ_TOPIC = os.getenv("ALERTS_DLQ_TOPIC", "security_alerts_dlq")
DLQ_PATH = os.getenv("DLQ_FILE_PATH", "/tmp/dlq/alerts.jsonl")  # nosec B108
DLQ_MAX_SIZE_MB = int(os.getenv("DLQ_MAX_SIZE_MB", "100"))
DLQ_ROTATE_COUNT = int(os.getenv("DLQ_ROTATE_COUNT", "5"))

import shutil

def _rotate_dlq_if_needed():
    """Rotate DLQ file when it exceeds size limit using atomic temp-rename."""
    try:
        if os.path.exists(DLQ_PATH) and os.path.getsize(DLQ_PATH) / (1024 * 1024) > DLQ_MAX_SIZE_MB:
            tmp_path = f"{DLQ_PATH}.tmp"
            for i in range(DLQ_ROTATE_COUNT - 1, 0, -1):
                src, dst = f"{DLQ_PATH}.{i}", f"{DLQ_PATH}.{i + 1}"
                if os.path.exists(src): os.replace(src, dst)
            os.replace(DLQ_PATH, f"{DLQ_PATH}.1")
            # Recreate empty DLQ file atomically
            open(DLQ_PATH, 'a').close()
            logger.info(f"Atomic rotated DLQ file.")
    except Exception as e:
        logger.error(f"DLQ rotation failed: {e}")

Base.metadata.create_all(bind=engine)

def get_dlq_producer():
    try:
        return KafkaProducer(
            bootstrap_servers=[b.strip() for b in brokers.split(',') if b.strip()],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=3,
            request_timeout_ms=5000
        )
    except Exception as e:
        logger.warning(f"Could not connect DLQ KafkaProducer: {e}")
        return None

_dlq_file_lock = threading.Lock()

def write_to_file_dlq(item, error_msg):
    try:
        dlq_dir = os.path.dirname(DLQ_PATH)
        if dlq_dir:
            os.makedirs(dlq_dir, exist_ok=True)
        _rotate_dlq_if_needed()
        with _dlq_file_lock:
            with open(DLQ_PATH, "a", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps({"error": str(error_msg), "alert": item, "timestamp": time.time()}) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as ex:
        logger.error(f"Fallback file DLQ append failed: {ex}")

def send_to_dlq(dlq_producer, item, error_msg, timeout=2.0):
    """Best-effort Kafka DLQ; never raises."""
    try:
        if dlq_producer is None:
            return
        dlq_payload = {"error": error_msg, "alert": item, "timestamp": time.time()}
        future = dlq_producer.send(DLQ_TOPIC, dlq_payload)
        future.get(timeout=timeout)
    except Exception as e:
        logger.error("Failed to send to Kafka DLQ topic: %s", e)

def run_sink():
    broker_list = [b.strip() for b in brokers.split(',') if b.strip()]
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=broker_list,
        group_id="tsoc-db-sink-group",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda m: m
    )
    dlq_producer = get_dlq_producer()

    MAX_BATCH_SIZE = 100
    MAX_COMMIT_RETRIES = 3
    batch = []
    last_commit = time.time()

    def _atomic_dlq_write(item, error_msg):
        """Append-only thread-safe DLQ write with flock + fsync."""
        write_to_file_dlq(item, error_msg)

    def _safe_dlq_send(alert_id, raw_item, error_msg):
        """Best-effort DLQ with local file fallback; never blocks caller."""
        try:
            send_to_dlq(dlq_producer, raw_item, error_msg, timeout=2.0)
        except Exception as e:
            logger.error("DLQ send failed for %s: %s", alert_id, e)
        _atomic_dlq_write(raw_item, error_msg)

    def process_batch(current_batch):
        """Processes an entire batch within a single DB session using savepoints for item isolation."""
        offsets_map = {}
        db = SessionLocal(expire_on_commit=False)
        try:
            for alert_obj, raw_item, tp, offset in current_batch:
                try:
                    with db.begin_nested():
                        existing = db.query(Alert).filter(Alert.alert_id == alert_obj.alert_id).first()
                        if existing:
                            existing.severity = alert_obj.severity
                            existing.confidence_score = alert_obj.confidence_score
                            existing.evidence = alert_obj.evidence
                            existing.timestamp = alert_obj.timestamp
                            existing.threat_class = alert_obj.threat_class
                            existing.event_type = alert_obj.event_type
                            existing.source_ip = alert_obj.source_ip
                            existing.destination_ip = alert_obj.destination_ip
                        else:
                            db.add(alert_obj)
                        db.flush()
                    offsets_map[tp] = max(offsets_map.get(tp, -1), offset + 1)
                except Exception as item_err:
                    # Item-level data formatting/integrity issue: isolate to DLQ and advance offset
                    logger.error("Item processing failed for alert %s: %s", raw_item.get('alert_id'), item_err)
                    _safe_dlq_send(raw_item.get('alert_id', ''), raw_item, str(item_err))
                    offsets_map[tp] = max(offsets_map.get(tp, -1), offset + 1)
            db.commit()
            return offsets_map
        except Exception as batch_err:
            # DB connection/commit error: rollback and DO NOT advance offsets so batch is safely retried
            db.rollback()
            logger.error("Batch DB commit failure (will retry on next cycle): %s", batch_err)
            return {}
        finally:
            db.close()

    consecutive_commit_failures = 0
    MAX_CONSECUTIVE_FAILURES = 5

    PANIC_BATCH_SIZE = 150  # Hard guard: never allow batch to grow beyond this; force DLQ immediately

    while True:
        # Flow control: do not poll new records if current batch is at capacity or commit is failing
        if len(batch) < MAX_BATCH_SIZE:
            try:
                records = consumer.poll(timeout_ms=1000)
            except Exception as poll_err:
                logger.error("Consumer poll error: %s", poll_err)
                records = {}
            if records:
                for tp, messages in records.items():
                    for msg in messages:
                        try:
                            data = json.loads(msg.value.decode("utf-8"))
                            if not data.get("alert_id"):
                                continue
                            if isinstance(data.get("evidence"), (dict, list)):
                                data["evidence"] = json.dumps(data["evidence"])
                            alert_obj = Alert(**{k: v for k, v in data.items() if hasattr(Alert, k)})
                            batch.append((alert_obj, data, tp, msg.offset))
                        except Exception as e:
                            logger.error("Skip bad message: %s", e)
        else:
            records = {}
            logger.debug("Batch at capacity (%d); pausing poll until commit succeeds", len(batch))

        # Commit on size or time
        if (len(batch) >= MAX_BATCH_SIZE) or (len(batch) > 0 and time.time() - last_commit >= 5):
            processed_offsets = process_batch(batch)

            if processed_offsets:
                commit_success = False
                for attempt in range(MAX_COMMIT_RETRIES):
                    try:
                        offsets_to_commit = {tp: OffsetAndMetadata(off, '') for tp, off in processed_offsets.items()}
                        consumer.commit(offsets=offsets_to_commit)
                        commit_success = True
                        consecutive_commit_failures = 0
                        break
                    except Exception as commit_err:
                        logger.error("Kafka offset commit attempt %d failed: %s", attempt + 1, commit_err)
                        time.sleep(0.5 * (attempt + 1))

                if commit_success:
                    batch.clear()
                    last_commit = time.time()
                else:
                    consecutive_commit_failures += 1
                    logger.warning("Kafka offset commit failed (failure count: %d); batch retained for retry", consecutive_commit_failures)
                    # Exponential backoff on persistent broker failure to prevent busy-spin
                    backoff_delay = min(5.0, 0.5 * (2 ** min(consecutive_commit_failures, 4)))
                    time.sleep(backoff_delay)

                    # If failures persist beyond threshold, route current batch to emergency DLQ to prevent indefinite stall
                    if consecutive_commit_failures >= MAX_CONSECUTIVE_FAILURES:
                        logger.critical("Persistent Kafka commit failure threshold reached. Evacuating %d alerts to file DLQ.", len(batch))
                        for alert_obj, raw_item, tp, offset in batch:
                            _atomic_dlq_write(raw_item, "KafkaCommitFailureThresholdExceeded")
                        batch.clear()
                        last_commit = time.time()
                        consecutive_commit_failures = 0
            else:
                last_commit = time.time()

            # Flush DLQ if any
            if dlq_producer:
                try:
                    dlq_producer.flush(timeout=5)
                except Exception as ex:
                    logger.error("DLQ flush error: %s", ex)

        if len(batch) >= PANIC_BATCH_SIZE:
            logger.critical("PANIC: Batch exceeded hard guard (%d); evacuating to DLQ immediately.", len(batch))
            for alert_obj, raw_item, tp, offset in batch:
                _atomic_dlq_write(raw_item, "BatchPanicThresholdExceeded")
            batch.clear()
            last_commit = time.time()
            consecutive_commit_failures = 0

        # Sleep briefly to avoid tight loop when idle
        if not records:
            time.sleep(0.1)


if __name__ == "__main__":
    logger.info("Starting Kafka to Postgres sink...")
    run_sink()
