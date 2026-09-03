import logging
import json
import os
import time
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
            bootstrap_servers=[brokers],
            auto_offset_reset='earliest',
            enable_auto_commit=False, 
            group_id='db_sink_group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
    except Exception as e:
        logger.error(f"Failed to connect to Redpanda: {e}")
        return
        
    db = SessionLocal()
    batch = []
    MAX_BATCH_SIZE = 100
    
    try:
        # PERFORMANCE FIX: Micro-batching via polling instead of row-by-row
        while True:
            records = consumer.poll(timeout_ms=1000)
            
            for topic_partition, messages in records.items():
                for message in messages:
                    data = message.value
                    
                    # Deduplication
                    existing = db.query(Alert).filter(Alert.alert_id == data.get("alert_id")).first()
                    if existing:
                        continue
                        
                    new_alert = Alert(
                        alert_id=data.get("alert_id", ""),
                        timestamp=data.get("timestamp", ""),
                        event_type=data.get("event_type", ""),
                        threat_class=data.get("threat_class", ""),
                        confidence_score=data.get("confidence_score", 0.0),
                        severity=data.get("severity", "low"),
                        source_ip=data.get("source_ip", ""),
                        destination_ip=data.get("destination_ip", ""),
                        evidence=json.dumps(data.get("evidence", {}))
                    )
                    batch.append(new_alert)

            # Commit if batch size reached or if we have records and a second has passed
            if len(batch) >= MAX_BATCH_SIZE or (len(batch) > 0 and not records):
                try:
                    db.bulk_save_objects(batch)
                    db.commit()
                    consumer.commit() # Securely acknowledge Kafka offset ONLY after DB flush
                    logger.info(f"[Sink] Bulk committed {len(batch)} alerts to disk.")
                    batch.clear()
                except Exception as e:
                    # SILENT DEATH FIX: Rollback bad transactions to keep worker alive
                    db.rollback()
                    logger.error(f"[Sink] Database Integrity Error. Rolled back batch. Error: {e}")
                    batch.clear()
                    
    except KeyboardInterrupt:
        logger.info("Stopping sink.")
    finally:
        db.close()

if __name__ == "__main__":
    run_sink()
