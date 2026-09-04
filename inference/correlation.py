import json
import time
import os
import redis
import uuid
import logging
from inference.risk import calculate_risk_score

logger = logging.getLogger(__name__)

# Atomic Lua script: push + trim + expire + len + nx dedup (without heavy snapshot return)
CORRELATE_LUA = """
local key_name = KEYS[1]
local dedup_name = KEYS[2]
local alert_json = ARGV[1]
local window = tonumber(ARGV[2])
local safe_threat = ARGV[3]

redis.call('lpush', key_name, alert_json)
redis.call('ltrim', key_name, 0, 99)
redis.call('expire', key_name, window)
redis.call('expire', dedup_name, window)
local len_list = redis.call('llen', key_name)
local incident = 0
if len_list >= 2 then
    local was_set = redis.call('set', dedup_name, '1', 'nx', 'ex', window)
    if was_set == 1 or was_set == true or was_set == 'OK' then
        incident = 1
    else
        incident = 0
    end
else
    incident = 0
end
return {len_list, incident, redis.call('lrange', key_name, 0, -1)}
"""

class IncidentCorrelator:
    def __init__(self):
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_password = os.getenv("REDIS_PASSWORD", None)
        redis_ssl = os.getenv("REDIS_SSL", "false").lower() in ("true", "1", "yes")

        pool = redis.ConnectionPool(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            ssl=redis_ssl,
            db=0,
            decode_responses=True,
            socket_timeout=2.0,
            max_connections=50,
            retry_on_timeout=True,
            health_check_interval=30
        )
        self.redis = redis.Redis(connection_pool=pool)
        self.time_window_sec = 300
        self._lua = self.redis.register_script(CORRELATE_LUA)

    def add_alert(self, alert, threshold=80.0):
        import re
        # Strict allow-list: alphanumeric, dot, hyphen, colon (IPv6), underscore only; reject injection chars
        safe_re = re.compile(r"^[A-Za-z0-9_.:-]+$")
        raw_src = str(alert.get("source_ip", "127.0.0.1"))
        src_ip = raw_src.strip()
        if not safe_re.match(src_ip) or len(src_ip) > 45:
            logger.warning("Invalid source_ip rejected: %r", raw_src)
            return None
        threat_class = str(alert.get("threat_class", "unknown"))
        # Strict threat class sanitization: only allow alphanumerics, space->underscore, drop others
        safe_threat = re.sub(r"[^A-Za-z0-9_ ]", "", threat_class)
        safe_threat = safe_threat.replace(" ", "_")[:64]
        if not safe_threat:
            safe_threat = "unknown"
        key_name = f"{{{src_ip}}}:alerts"
        dedup_name = f"{{{src_ip}}}:dedup:{safe_threat}"

        # Execute purely atomic Redis Lua script (push + trim + expire + len + nx dedup + snapshot)
        try:
            result = self._lua(
                keys=[key_name, dedup_name],
                args=[
                    json.dumps(alert),
                    str(self.time_window_sec),
                    safe_threat
                ]
            )
            len_list = int(result[0])
            incident_flag = int(result[1])
            if incident_flag == 1:
                # Consistency fix: evidence comes from the atomic Lua return, not a separate lrange
                raw_alerts = result[2] if len(result) > 2 else []
                threat_classes_set = set()
                affected_entities_set = {src_ip}
                related_alert_ids = []
                tactics_set = set()
                parsed_alerts_list = []
                sev_weights = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}
                max_sev = alert.get("severity", "high")

                for raw_a in raw_alerts:
                    try:
                        parsed_a = json.loads(raw_a) if isinstance(raw_a, str) else raw_a
                        if isinstance(parsed_a, dict):
                            parsed_alerts_list.append(parsed_a)
                            tc = parsed_a.get("threat_class")
                            if tc:
                                threat_classes_set.add(tc)
                            dst = parsed_a.get("destination_ip")
                            if dst:
                                affected_entities_set.add(dst)
                            aid = parsed_a.get("alert_id")
                            if aid and aid not in related_alert_ids:
                                related_alert_ids.append(aid)
                            tactic = parsed_a.get("mitre_tactic") or parsed_a.get("tactic")
                            if tactic:
                                tactics_set.add(tactic)
                            a_sev = str(parsed_a.get("severity", "low")).lower()
                            if sev_weights.get(a_sev, 25.0) >= sev_weights.get(str(max_sev).lower(), 25.0):
                                max_sev = a_sev
                    except Exception as parse_err:
                        logger.debug("Failed parsing historical alert in correlation window: %s", parse_err)

                if not parsed_alerts_list:
                    parsed_alerts_list.append(alert)
                if not threat_classes_set:
                    threat_classes_set.add(threat_class)
                if alert.get("alert_id") and alert.get("alert_id") not in related_alert_ids:
                    related_alert_ids.append(alert.get("alert_id"))

                threat_list = list(threat_classes_set)
                entities_list = list(affected_entities_set)
                calculated_risk = calculate_risk_score(parsed_alerts_list)
                final_risk = max(calculated_risk, float(threshold))

                return {
                    "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                    "source_ip": src_ip,
                    "affected_entities": entities_list,
                    "threat_classes": threat_list,
                    "tactics": list(tactics_set),
                    "highest_risk": final_risk,
                    "severity": max_sev,
                    "risk_score": float(final_risk),
                    "created_timestamp": int(time.time()),
                    "timestamp": int(time.time() * 1000),
                    "status": "active",
                    "evidence_summary": f"Correlated {len(threat_list)} threat vector(s) ({', '.join(threat_list)}) across {len(related_alert_ids)} alert(s) involving {src_ip}",
                    "related_alert_ids": related_alert_ids
                }
        except redis.RedisError as e:
            logger.error("Redis correlation execution failed for %s: %s", src_ip, e)
            raise
        return None
