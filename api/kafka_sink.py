import jsonschema
import logging
import json
import os
import time
import uuid
import fcntl
import signal
import sys
import threading
from kafka import KafkaConsumer, KafkaProducer
from kafka.structs import OffsetAndMetadata, TopicPartition
from api.database import SessionLocal, engine, Base
from api.models import Alert

logger = logging.getLogger(__name__)

brokers = os.getenv("REDPANDA_BROKERS", "soc-redpanda-cluster.prod.svc.cluster.local:9092")
topic = os.getenv("ALERTS_TOPIC", "security_alerts")
DLQ_TOPIC = os.getenv("ALERTS_DLQ_TOPIC", "security_alerts_dlq")

# Path Sanitization and Directory Whitelisting to prevent path traversal
_raw_dlq_path = os.getenv("DLQ_FILE_PATH", "/tmp/dlq/alerts.jsonl")  # nosec B108
_allowed_base_dir = os.path.abspath("/tmp/dlq")  # nosec B108
_resolved_dlq_path = os.path.abspath(_raw_dlq_path)

if not _resolved_dlq_path.startswith(_allowed_base_dir):
    logger.warning("Dangerous or out-of-bounds DLQ path rejected (%s); defaulting to %s", _raw_dlq_path, "/tmp/dlq/alerts.jsonl")  # nosec B108
    DLQ_PATH = "/tmp/dlq/alerts.jsonl"  # nosec B108
else:
    DLQ_PATH = _resolved_dlq_path

DLQ_LOCK_PATH = f"{DLQ_PATH}.lock"
DLQ_MAX_SIZE_MB = int(os.getenv("DLQ_MAX_SIZE_MB", "100"))
DLQ_ROTATE_COUNT = int(os.getenv("DLQ_ROTATE_COUNT", "5"))

import shutil

def _rotate_dlq_if_needed():
    """Rotate DLQ file when it exceeds size limit using atomic temp-rename."""
    try:
        if os.path.exists(DLQ_PATH) and (os.path.getsize(DLQ_PATH) / (1024 * 1024)) > DLQ_MAX_SIZE_MB:
            for i in range(DLQ_ROTATE_COUNT - 1, 0, -1):
                src, dst = f"{DLQ_PATH}.{i}", f"{DLQ_PATH}.{i + 1}"
                if os.path.exists(src):
                    os.replace(src, dst)
            os.replace(DLQ_PATH, f"{DLQ_PATH}.1")
            # Recreate empty DLQ file atomically
            open(DLQ_PATH, 'a').close()
            logger.info("Atomic rotated DLQ file.")
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

_dlq_thread_lock = threading.Lock()

def write_to_file_dlq(item, error_msg):
    try:
        dlq_dir = os.path.dirname(DLQ_PATH)
        if dlq_dir:
            os.makedirs(dlq_dir, exist_ok=True)
        with _dlq_thread_lock:
            # Process-safe inter-pod/inter-process lock file
            with open(DLQ_LOCK_PATH, "a", encoding="utf-8") as lock_file:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    _rotate_dlq_if_needed()
                    with open(DLQ_PATH, "a", encoding="utf-8") as f:
                        f.write(json.dumps({"error": str(error_msg), "alert": item, "timestamp": time.time()}) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
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
            for raw_item, tp, offset in current_batch:
                try:
                    alert_dict = {k: v for k, v in raw_item.items() if hasattr(Alert, k)}
                    aid = alert_dict.get("alert_id")
                    with db.begin_nested():
                        existing = db.query(Alert).filter(Alert.alert_id == aid).first()
                        if existing:
                            for k, v in alert_dict.items():
                                if k != "id":
                                    setattr(existing, k, v)
                        else:
                            alert_obj = Alert(**alert_dict)
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

    # Hard panic guard raised: 500 allows normal flush cycles to run long before triggering emergency evacuation.
    # 150 was too low, causing unnecessary mass exfiltration to DLQ under moderate load.
    PANIC_BATCH_SIZE = 500

    running = True

    def _handle_shutdown_signal(sig, frame):
        nonlocal running
        logger.info("Shutdown signal (%s) received. Commencing graceful Kafka sink termination...", sig)
        running = False

    signal.signal(signal.SIGTERM, _handle_shutdown_signal)
    signal.signal(signal.SIGINT, _handle_shutdown_signal)

    while running:
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
                            batch.append((data, tp, msg.offset))
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
                        max_offsets = {}
                        for raw_item, tp, offset in batch:
                            _atomic_dlq_write(raw_item, "KafkaCommitFailureThresholdExceeded")
                            max_offsets[tp] = max(max_offsets.get(tp, -1), offset + 1)
                        if max_offsets:
                            try:
                                consumer.commit(offsets={tp: OffsetAndMetadata(off, '') for tp, off in max_offsets.items()})
                            except Exception as ex:
                                logger.warning("Failed committing offsets after Kafka DLQ evacuation: %s", ex)
                        batch.clear()
                        last_commit = time.time()
                        consecutive_commit_failures = 0
            else:
                consecutive_commit_failures += 1
                logger.warning("Database commit failed (failure count: %d); batch retained for retry", consecutive_commit_failures)
                backoff_delay = min(5.0, 0.5 * (2 ** min(consecutive_commit_failures, 4)))
                time.sleep(backoff_delay)
                if consecutive_commit_failures >= MAX_CONSECUTIVE_FAILURES:
                    logger.critical("Persistent Database commit failure threshold reached. Evacuating %d alerts.", len(batch))
                    max_offsets = {}
                    for raw_item, tp, offset in batch:
                        _atomic_dlq_write(raw_item, "DatabaseCommitFailureThresholdExceeded")
                        max_offsets[tp] = max(max_offsets.get(tp, -1), offset + 1)
                    if max_offsets:
                        try:
                            consumer.commit(offsets={tp: OffsetAndMetadata(off, '') for tp, off in max_offsets.items()})
                        except Exception as ex:
                            logger.warning("Failed committing offsets after DB DLQ evacuation: %s", ex)
                    batch.clear()
                    last_commit = time.time()
                    consecutive_commit_failures = 0

            # Flush DLQ if any
            if dlq_producer:
                try:
                    dlq_producer.flush(timeout=5)
                except Exception as ex:
                    logger.error("DLQ flush error: %s", ex)

        if len(batch) >= PANIC_BATCH_SIZE:
            logger.critical("PANIC: Batch exceeded hard guard (%d); evacuating to DLQ immediately.", len(batch))
            max_offsets = {}
            for raw_item, tp, offset in batch:
                _atomic_dlq_write(raw_item, "BatchPanicThresholdExceeded")
                max_offsets[tp] = max(max_offsets.get(tp, -1), offset + 1)
            if max_offsets:
                try:
                    consumer.commit(offsets={tp: OffsetAndMetadata(off, '') for tp, off in max_offsets.items()})
                except Exception as ex:
                    logger.warning("Failed committing offsets after panic DLQ evacuation: %s", ex)
            batch.clear()
            last_commit = time.time()
            consecutive_commit_failures = 0

        # Sleep briefly to avoid tight loop when idle
        if not records:
            time.sleep(0.1)

    logger.info("Graceful shutdown: loop exited. Processing any remaining %d items in batch...", len(batch))
    if len(batch) > 0:
        processed_offsets = process_batch(batch)
        if processed_offsets:
            try:
                offsets_to_commit = {tp: OffsetAndMetadata(off, '') for tp, off in processed_offsets.items()}
                consumer.commit(offsets=offsets_to_commit)
                logger.info("Graceful shutdown: Successfully committed final batch offsets.")
            except Exception as commit_err:
                logger.error("Graceful shutdown: Final Kafka offset commit failed: %s", commit_err)
    if dlq_producer:
        logger.info("Graceful shutdown: Flushing DLQ producer...")
        dlq_producer.flush(timeout=5)
        dlq_producer.close()
    logger.info("Graceful shutdown: Closing Kafka consumer...")
    consumer.close(autocommit=False)
    logger.info("Kafka sink graceful shutdown complete.")


if __name__ == "__main__":
    logger.info("Starting Kafka to Postgres sink...")
    run_sink()
