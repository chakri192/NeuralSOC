import json
import time
import os
import redis
import uuid
import logging
import ipaddress
import ssl
from inference.risk import calculate_risk_score

logger = logging.getLogger(__name__)

# Atomic Lua script: push + trim + non-extending window expire + count + dedup with priority (optimized snapshot return)
CORRELATE_LUA = """
local key_name = KEYS[1]
local dedup_name = KEYS[2]
local alert_json = ARGV[1]
local window = tonumber(ARGV[2])
local safe_threat = ARGV[3]
local severity_score = tonumber(ARGV[4])
local alert_id = ARGV[5] or ""
local is_replay = ARGV[6] or "0"

-- Replay defense: deduplicate identical alert_ids within sliding window
if alert_id ~= "" then
    local seen_key = key_name .. ":seen"
    local is_dup = redis.call('sismember', seen_key, alert_id)
    if is_dup == 1 and is_replay ~= "1" then
        return {0, 0, {}}
    end
    redis.call('sadd', seen_key, alert_id)
    local ttl_seen = redis.call('ttl', seen_key)
    if ttl_seen < 0 then
        redis.call('expire', seen_key, window)
    end
end

redis.call('lpush', key_name, alert_json)
redis.call('ltrim', key_name, 0, 99)
local ttl_list = redis.call('ttl', key_name)
if ttl_list < 0 then
    redis.call('expire', key_name, window)
end

local count_key = key_name .. ":cnt"
local total_count = redis.call('incr', count_key)
local ttl_cnt = redis.call('ttl', count_key)
if ttl_cnt < 0 then
    redis.call('expire', count_key, window)
end

local current_max = tonumber(redis.call('get', dedup_name) or "0")
local incident = 0

if total_count >= 2 then
    if current_max == 0 or severity_score > current_max or total_count == 2 or (total_count > 2 and total_count % 5 == 0) then
        incident = 1
    end
end

if current_max == 0 then
    redis.call('set', dedup_name, tostring(severity_score), 'ex', window)
elseif severity_score > current_max then
    local ttl_dedup = redis.call('ttl', dedup_name)
    if ttl_dedup > 0 then
        redis.call('set', dedup_name, tostring(severity_score), 'ex', ttl_dedup)
    else
        redis.call('set', dedup_name, tostring(severity_score), 'ex', window)
    end
end

local alerts_snapshot = {}
if incident == 1 then
    alerts_snapshot = redis.call('lrange', key_name, 0, -1)
end
return {total_count, incident, alerts_snapshot}
"""

ROLLBACK_LUA = """
local key_name = KEYS[1]
local dedup_name = KEYS[2]
local seen_key = key_name .. ":seen"
local count_key = key_name .. ":cnt"

local alert_json = ARGV[1]
local alert_id = ARGV[2]
local safe_threat = ARGV[3]

if alert_id ~= "" then
    redis.call('srem', seen_key, alert_id)
end

if alert_json ~= "" then
    local removed = redis.call('lrem', key_name, 1, alert_json)
    if removed > 0 then
        local current_cnt = tonumber(redis.call('get', count_key) or "0")
        if current_cnt > 1 then
            redis.call('decr', count_key)
        elseif current_cnt == 1 then
            redis.call('del', count_key)
        end
    end
end
return 1
"""

class IncidentCorrelator:
    def __init__(self):
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_password = os.getenv("REDIS_PASSWORD", None)
        redis_ssl = os.getenv("REDIS_SSL", "false").lower() in ("true", "1", "yes")

        pool_kwargs = dict(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            ssl=redis_ssl,
            db=0,
            decode_responses=True,
            socket_timeout=2.0,
            max_connections=50,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        # Enforce TLS certificate verification when SSL is enabled to prevent MITM
        if redis_ssl:
            pool_kwargs["ssl_cert_reqs"] = "required"
            redis_ca_cert = os.getenv("REDIS_CA_CERT_PATH")
            if redis_ca_cert and os.path.exists(redis_ca_cert):
                pool_kwargs["ssl_ca_certs"] = redis_ca_cert
            else:
                try:
                    import certifi
                    pool_kwargs["ssl_ca_certs"] = certifi.where()
                except ImportError:
                    paths = ssl.get_default_verify_paths()
                    if paths.cafile:
                        pool_kwargs["ssl_ca_certs"] = paths.cafile
                    elif paths.capath:
                        pool_kwargs["ssl_ca_path"] = paths.capath

        pool = redis.ConnectionPool(**pool_kwargs)
        self.redis = redis.Redis(connection_pool=pool)
        self.time_window_sec = 300
        self._lua = self.redis.register_script(CORRELATE_LUA)
        self._rollback_lua = self.redis.register_script(ROLLBACK_LUA)

    def add_alert(self, alert, threshold=80.0):
        import re
        raw_src = str(alert.get("source_ip", "127.0.0.1")).strip()
        # Strict IP validation to prevent Redis key injection and newline attacks
        try:
            addr = ipaddress.ip_address(raw_src)
            src_ip = str(addr)
        except ValueError:
            logger.warning("Invalid source_ip rejected: %r", raw_src)
            return None
        if len(src_ip) > 45:
            logger.warning("Invalid source_ip length rejected: %r", raw_src)
            return None

        threat_class = str(alert.get("threat_class", "unknown"))
        # Strict threat class sanitization: only allow alphanumerics, space->underscore, drop others
        safe_threat = re.sub(r"[^A-Za-z0-9_ ]", "", threat_class)
        safe_threat = safe_threat.replace(" ", "_")[:64]
        if not safe_threat:
            safe_threat = "unknown"
        key_name = f"{{{src_ip}}}:alerts"
        dedup_name = f"{{{src_ip}}}:dedup:{safe_threat}"

        # Determine numeric severity score for thresholding / escalation
        sev_weights = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}
        raw_sev = str(alert.get("severity", "low")).lower().strip()
        if raw_sev not in sev_weights:
            raw_sev = "low"
        sev_score = sev_weights[raw_sev]

        # Execute purely atomic Redis Lua script (push + trim + expire + len + dedup with escalation + snapshot)
        try:
            result = self._lua(
                keys=[key_name, dedup_name],
                args=[
                    json.dumps(alert),
                    str(self.time_window_sec),
                    safe_threat,
                    str(sev_score),
                    str(alert.get("alert_id", "")),
                    "1" if alert.get("is_replay") else "0"
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
                final_risk = float(calculated_risk)

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
                    "related_alert_ids": related_alert_ids,
                    "trace_id": alert.get("trace_id")
                }
        except redis.RedisError as e:
            logger.error("Redis correlation execution failed for %s: %s", src_ip, e)
            raise
        return None

    def rollback_alert_seen(self, alert: dict):
        """
        Compensating transaction: atomically removes alert_id from the seen set,
        removes the alert from the sliding window list, and decrements the counter
        in Redis if downstream incident emission fails. Allows DLQ replay to re-evaluate the incident.
        """
        try:
            import re
            raw_src = str(alert.get("source_ip", "127.0.0.1")).strip()
            addr = ipaddress.ip_address(raw_src)
            src_ip = str(addr)
            aid = str(alert.get("alert_id", "")).strip()

            threat_class = str(alert.get("threat_class", "unknown"))
            safe_threat = re.sub(r"[^A-Za-z0-9_ ]", "", threat_class)
            safe_threat = safe_threat.replace(" ", "_")[:64] or "unknown"

            key_name = f"{{{src_ip}}}:alerts"
            dedup_name = f"{{{src_ip}}}:dedup:{safe_threat}"

            self._rollback_lua(
                keys=[key_name, dedup_name],
                args=[
                    json.dumps(alert),
                    aid,
                    safe_threat
                ]
            )
            logger.info("Rolled back alert %s state in Redis for %s", aid, src_ip)
        except Exception as e:
            logger.warning("Failed to rollback alert state in Redis: %s", e)

