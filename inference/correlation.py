import uuid
import time
from datetime import datetime, timezone
from inference.risk import calculate_risk_score

import redis
import json
import os

class IncidentCorrelator:
    def __init__(self):
        # Strict fallback enforcement
        redis_host = os.getenv("REDIS_HOST", "localhost")
        self.redis = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)
        self.time_window_sec = int(os.getenv("CORRELATION_WINDOW", "300"))

    def add_alert(self, alert: dict):
        src_ip = alert.get("source_ip")
        if not src_ip or src_ip == "unknown":
            return None

        # Store alert in Redis list with TTL
        key = f"alerts:{src_ip}"
        self.redis.lpush(key, json.dumps(alert))
        self.redis.expire(key, self.time_window_sec)

        # Retrieve and correlate
        records = self.redis.lrange(key, 0, -1)
        records = [json.loads(r) for r in records]
        
        # Incident generation logic...
        tactics = set()
        highest_risk = 0.0
        
        for r in records:
            if "mitre_tactic" in r:
                tactics.add(r["mitre_tactic"])
            risk = r.get("risk_score", 0.0)
            if risk > highest_risk:
                highest_risk = risk

        if len(tactics) >= 2 or highest_risk >= 80.0:
            incident = {
                "incident_id": str(uuid.uuid4()),
                "source_ip": src_ip,
                "severity": "critical" if highest_risk >= 90.0 else "high",
                "risk_score": highest_risk,
                "related_alerts": len(records),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            # Clear correlated records so we don't duplicate
            self.redis.delete(key)
            return incident
            
        return None
