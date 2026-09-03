import logging
logger = logging.getLogger(__name__)
from redis.lock import Lock
import uuid
import time
import json
import os
from datetime import datetime, timezone
import redis
import redis.lock
from inference.risk import calculate_risk_score

class IncidentCorrelator:
    def __init__(self):
        redis_host = os.getenv("REDIS_HOST", "localhost")
        pool = redis.ConnectionPool(host=redis_host, port=6379, db=0, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0, max_connections=100, password=os.getenv('REDIS_PASSWORD', ''), ssl=True, ssl_cert_reqs='none')
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
        if not src_ip or str(src_ip).strip() == "" or ".." in str(src_ip) or "/" in str(src_ip):
            return None
            
        key = f"alerts:{src_ip}"
        time_ms = int(time.time() * 1000)
        threshold = getattr(self, 'threshold', 80.0)
        
        try:
            with Lock(self.redis, lock_name=f"lock:{src_ip}", timeout=10, blocking_timeout=2):
                raw = self._correlate_script(keys=[key], args=[self.time_window_sec, 100, json.dumps(alert)])
                if not raw:
                    return None
                    
                records = raw
                if not records:
                    return None
                    
                tactics = set()
                highest_risk = 0.0
                
                for r in records:
                    if isinstance(r, (bytes, str)):
                        try:
                            parsed = json.loads(r)
                            tactics.add(parsed.get("tactic", "unknown"))
                            highest_risk = max(highest_risk, float(parsed.get("risk_score", 0.0)))
                        except Exception:
                            continue
                            
                if len(tactics) >= 2 or highest_risk >= threshold:
                    incident = {
                        "incident_id": str(uuid.uuid4()),
                        "source_ip": src_ip,
                        "tactics": list(tactics),
                        "max_risk_score": highest_risk,
                        "evidence_count": len(records),
                        "timestamp": time_ms
                    }
                    self.redis.setex(f"incident:{incident['incident_id']}", self.time_window_sec, json.dumps(incident))
                    return incident
                return None
        except Exception as e:
            logger.error(f"Correlation error: {e}")
            return None