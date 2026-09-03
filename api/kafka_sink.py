import jsonschema
import logging
import json
import os
import time
import uuid
from kafka import KafkaConsumer
from api.database import SessionLocal, engine, Base
from api.models import Alert

logger = logging.getLogger(__name__)

brokers = os.getenv("REDPANDA_BROKERS", "soc-redpanda-cluster.prod.svc.cluster.local:9092")
topic = os.getenv("ALERTS_TOPIC", "security_alerts")

Base.metadata.create_all(bind=engine)

def run_sink():
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=[b.strip() for b in brokers.split(',') if b.strip()],
        group_id="tsoc-db-sink-group",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda m: m
    )
    
    db = SessionLocal(expire_on_commit=False)
    MAX_BATCH_SIZE = 100
    batch = []
    last_commit = time.time()
    
    try:
        while True:
            records = consumer.poll(timeout_ms=1000)
            if records:
                for tp, messages in records.items():
                    for msg in messages:
                        try:
                            data = json.loads(msg.value.decode("utf-8"))
                            jsonschema.validate(data, {"type": "object", "properties": {"alert_id": {"type": "string"}, "timestamp": {"type": "string"}, "source_ip": {"type": "string"}, "threat_class": {"type": "string"}}, "required": ["alert_id", "timestamp", "source_ip", "threat_class"]})
                            if not data.get("alert_id"): continue
                            batch.append(Alert(**{k: v for k, v in data.items() if hasattr(Alert, k)}))
                        except Exception as e:
                            logger.error(f"Skip bad message: {e}")
                            import os, json, fcntl
                            try:
                                os.makedirs("/tmp/dlq", exist_ok=True)
                                with open("/tmp/dlq/alerts.jsonl", "a") as df:
                                    fcntl.flock(df, fcntl.LOCK_EX)
                                    df.write(json.dumps({"poison_pill": True, "err": str(e)}) + "\n")
                                    fcntl.flock(df, fcntl.LOCK_UN)
                            except:
                                pass
                            
            if (len(batch) >= MAX_BATCH_SIZE) or (len(batch) > 0 and time.time() - last_commit >= 5):
                try:
                    db.bulk_save_objects(batch)
                    db.commit()        # Commit Postgres FIRST
                    consumer.commit()   # Commit Kafka offsets SECOND
                except Exception as e:
                    db.rollback()
                    logger.error(f"Sink commit error: {e}")
                    try:
                        import os, json, fcntl
                        os.makedirs("/tmp/dlq", exist_ok=True)
                        with open("/tmp/dlq/alerts.jsonl", "a") as df:
                            fcntl.flock(df, fcntl.LOCK_EX)
                            df.write(json.dumps({"batch_len": len(batch), "err": str(e), "alerts": [{c.name: str(getattr(a, c.name)) for c in a.__table__.columns} for a in batch]}) + "\n")
                            df.flush() # Force flush before unlock
                            fcntl.flock(df, fcntl.LOCK_UN)
                    except Exception:
                        pass
                finally:
                    batch.clear() # ALWAYS clear batch to prevent infinite retry loops
                    last_commit = time.time()
    finally:
        db.close()

if __name__ == "__main__":
    logger.info("Starting Kafka to Postgres sink...")
    run_sink()
