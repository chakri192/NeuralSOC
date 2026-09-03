import logging
import json
import os
import time
import os
MAX_BATCH_SIZE = 100
from kafka import KafkaConsumer
from api.database import SessionLocal, engine, Base
from api.models import Alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sink")

# Initialize the database tables if they don't exist
Base.metadata.create_all(bind=engine)

def run_sink():
    logger.info("[*] Starting High-Throughput Redpanda-to-Database Sink...")
    brokers = os.environ.get("REDPANDA_BROKERS")
    if not brokers:
        raise RuntimeError("REDPANDA_BROKERS environment variable is missing")
    
    try:
        # DATA LOSS FIX: enable_auto_commit=False prevents dropped alerts
        consumer = KafkaConsumer(
            'security_alerts',
            bootstrap_servers=[b.strip() for b in brokers.split(',') if b.strip()],
            auto_offset_reset='earliest',
            enable_auto_commit=False, 
            group_id='db_sink_group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
    except Exception as e:
        logger.error(f"Failed to connect to Redpanda: {e}")
        return
        
    db = SessionLocal()
    import time
import os
MAX_BATCH_SIZE = 100
    batch = []
    last_commit = time.time()
    
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
                        continue
                        
        if len(batch) >= MAX_BATCH_SIZE or (len(batch) > 0 and time.time() - last_commit >= 5):
            try:
                db.bulk_save_objects(batch)
                db.flush()
                db.commit()
                consumer.commit()
                batch.clear()
                last_commit = time.time()
            except Exception as e:
                db.rollback()
                logger.error(f"Sink commit error: {e}")
                for msg in batch:
                    try:
                        import uuid
                        db.add(Alert(**msg.__dict__ if hasattr(msg, '__dict__') else msg))
                        db.commit()
                    except Exception:
                        db.rollback()
                        try:
                            os.makedirs("/tmp/dlq", exist_ok=True)
                            with open("/tmp/dlq/alerts.jsonl", "a") as df:
                                import json
                                df.write(json.dumps({"poison": msg.__dict__ if hasattr(msg, '__dict__') else msg, "err": str(e)}) + "
")
                        except Exception:
                            pass
                batch.clear()
                last_commit = time.time()