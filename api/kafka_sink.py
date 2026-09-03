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
    
    db = SessionLocal()
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
                            if not data.get("alert_id"): continue
                            batch.append(Alert(**data))
                        except Exception as e:
                            logger.error(f"Skip bad message: {e}")
                            try:
                                import os, json
                                os.makedirs("/tmp/dlq", exist_ok=True)
                                with open("/tmp/dlq/alerts.jsonl", "a") as df:
                                    df.write(json.dumps({"poison_pill": True, "err": str(e)}) + "
")
                            except:
                                pass
                            
            if (len(batch) >= MAX_BATCH_SIZE) or (len(batch) > 0 and time.time() - last_commit >= 5):
                try:
                    db.bulk_save_objects(batch)
                    db.flush()
                    consumer.commit()
                    db.commit()
                except Exception as e:
                    db.rollback()
                    logger.error(f"Sink commit error: {e}")
                    try:
                        import os, json
                        os.makedirs("/tmp/dlq", exist_ok=True)
                        with open("/tmp/dlq/alerts.jsonl", "a") as df:
                            df.write(json.dumps({"batch_len": len(batch), "err": str(e)}) + "\n")
                    except:
                        pass
                finally:
                    batch.clear()
                    last_commit = time.time()
    finally:
        db.close()

if __name__ == "__main__":
    logger.info("Starting Kafka to Postgres sink...")
    run_sink()
