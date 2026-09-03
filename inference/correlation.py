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
        pool = redis.ConnectionPool(host=redis_host, port=6379, db=0, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0, max_connections=100)
        self.redis = redis.Redis(connection_pool=pool)
        self.time_window_sec = int(os.getenv("CORRELATION_WINDOW", "300"))

        self._correlate_script = self.redis.register_script('''
            local key = KEYS[1]
            local window = tonumber(ARGV[1])
            local max_records = tonumber(ARGV[2])
            redis.call('LPUSH', key, ARGV[3])
            redis.call('LTRIM', key, 0, max_records - 1)
            redis.call('EXPIRE', key, window)
            local records = redis.call('LRANGE', key, 0, -1)
            return records
        ''')


    def add_alert(self, alert: dict):
        src_ip = alert.get("source_ip")
        if not src_ip or src_ip == "unknown":
            return None

        key = f"alerts:{src_ip}"
        raw_records = self._correlate_script(keys=[key], args=[self.time_window_sec, 100, json.dumps(alert)])
        records = []
        for r in raw_records:
            try:
                records.append(json.loads(r))
            except Exception:
                pass # Drop corrupt JSON (Fix 5.4 DoS)
        
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
