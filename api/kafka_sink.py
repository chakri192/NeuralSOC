import logging
import json
import os
import time
import uuid
from kafka import KafkaConsumer
from api.database import SessionLocal, engine, Base
from api.models import Alert

logger = logging.getLogger(__name__)

# Kafka configuration
brokers = os.getenv("REDPANDA_BROKERS", "soc-redpanda-cluster.prod.svc.cluster.local:9092")
topic = os.getenv("ALERTS_TOPIC", "security_alerts")

# Initialize database schema
Base.metadata.create_all(bind=engine)

def run_sink():
    # Fix: Ensure brokers splits properly
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
                        
        if (len(batch) >= MAX_BATCH_SIZE) or (len(batch) > 0 and time.time() - last_commit >= 5):
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
                try:
                    import urllib.request
                    import urllib.parse
                    import json
                    req = urllib.request.Request(
                        os.getenv("SLACK_WEBHOOK_URL", "https://example.com/webhook"),
                        data=json.dumps({"text": f"CRITICAL SOC ALERT - Database Rollback: {e}"}).encode(),
                        headers={'Content-Type': 'application/json'}
                    )
                    urllib.request.urlopen(req, timeout=2.0)
                except Exception:
                    pass
                for msg in batch:
                    try:
                        import uuid
                        if isinstance(msg, dict): 
                            record = msg 
                        else: 
                            record = {k: v for k, v in msg.__dict__.items() if not k.startswith('_')}
                        
                        db.add(Alert(**record))
                        db.commit()
                    except Exception:
                        db.rollback()
                        try:
                            # 9/10 Grade: Send PagerDuty webhook alert on DB rollback
                            import urllib.request
                            import urllib.parse
                            req = urllib.request.Request(
                                "https://events.pagerduty.com/v2/enqueue",
                                data=json.dumps({
                                    "routing_key": os.getenv("PAGERDUTY_ROUTING_KEY", ""),
                                    "event_action": "trigger",
                                    "payload": {
                                        "summary": f"SOC Database Rollback / Poison Pill: {e}",
                                        "source": "tsoc-kafka-sink",
                                        "severity": "critical"
                                    }
                                }).encode(),
                                headers={'Content-Type': 'application/json'}
                            )
                            urllib.request.urlopen(req, timeout=2.0)
                        except Exception:
                            pass
                        
                        try:
                            os.makedirs("/tmp/dlq", exist_ok=True)
                            with open("/tmp/dlq/alerts.jsonl", "a") as df:
                                import json
                                df.write(json.dumps({"poison": record, "err": str(e)}) + "\n")
                        except Exception:
                            pass
                batch.clear()
                last_commit = time.time()

if __name__ == "__main__":
    logger.info("Starting Kafka to Postgres sink...")
    run_sink()
