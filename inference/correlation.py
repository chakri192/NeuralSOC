import json
import time
import os
import redis
import uuid
import logging

logger = logging.getLogger(__name__)

class IncidentCorrelator:
    def __init__(self):
        pool = redis.ConnectionPool(host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0, decode_responses=True, socket_timeout=2.0, max_connections=100, password=os.getenv('REDIS_PASSWORD'), ssl=True, ssl_cert_reqs='required', ssl_ca_certs='/certs/ca.crt')
        self.redis = redis.Redis(connection_pool=pool)
        self.time_window_sec = 300
        self._correlate_script = self.redis.register_script('''
            local key = KEYS[1]
            local dedup = KEYS[2]
            local window = tonumber(ARGV[1])
            local alert_data = ARGV[2]
            if redis.call('GET', dedup) == "1" then return nil end
            redis.call('LPUSH', key, alert_data)
            redis.call('SET', dedup, "1", "EX", window)
            return "INCIDENT"
        ''')

    def add_alert(self, src_ip, alert, threshold=80.0):
        try:
            raw = self._correlate_script(keys=[f"alerts:{src_ip}", f"dedup:{src_ip}"], args=[self.time_window_sec, json.dumps(alert)])
            if raw == "INCIDENT":
                return {"incident_id": str(uuid.uuid4()), "source_ip": src_ip, "tactics": [], "highest_risk": threshold, "timestamp": int(time.time() * 1000)}
        except Exception:
            pass
        return None
