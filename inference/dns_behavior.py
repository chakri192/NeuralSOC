"""Per-source-host DNS behavioral tracking -- a genuinely different kind
of signal than the DGA CNN's per-domain character classification.

A single domain's character shape has a hard ceiling: a well-made
dictionary-style DGA domain (see SECURITY.md's suppobox/gozi discussion)
can be lexically indistinguishable from a legitimate two-word brand
name. But a DGA-infected host's *behavior* over time looks different
from normal browsing regardless of what any individual domain looks
like -- it typically generates and queries many distinct, never-seen
domains in a short window, and gets NXDOMAIN back for most of them
before the one live C2 domain resolves. This is directly motivated by a
real finding from this project's own Lumma Stealer pcap validation:
whitepepper.su, a genuinely malicious domain, was queried 10 times in a
tight window -- a burst pattern visible in DNS query volume alone, with
or without the CNN's per-domain verdict.

Reuses the caller's already-configured Redis connection
(inference/correlation.py's IncidentCorrelator already enforces
mandatory auth + TLS) rather than opening a second connection pool with
its own security configuration to audit and potentially drift from the
first.
"""
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Bounded the same way inference/correlation.py's own sliding-window
# state is: a single noisy or attacking host shouldn't be able to grow
# Redis memory without limit just by generating a lot of DNS activity.
MAX_TRACKED_DOMAINS = 200
DISTINCT_DOMAIN_BURST_THRESHOLD = 15
NXDOMAIN_RATE_THRESHOLD = 0.5
MIN_RESPONSES_FOR_NXDOMAIN_RATE = 5


def _validate_source_ip(raw_ip: str):
    """Strict IP validation, matching IncidentCorrelator.add_alert()'s
    own discipline -- source_ip here originates from network packet
    data (attacker-influenced), and building a Redis key by directly
    interpolating an unvalidated string would be a real key/command
    injection vector, not merely defensive paranoia."""
    try:
        addr = ipaddress.ip_address(str(raw_ip).strip())
    except ValueError:
        return None
    normalized = str(addr)
    if len(normalized) > 45:
        return None
    return normalized


class DnsBehaviorTracker:
    def __init__(self, redis_client, window_seconds: int = 60):
        self.redis = redis_client
        self.window_seconds = window_seconds

    def record_query(self, source_ip: str, domain: str) -> None:
        """Call once per outbound DNS query seen for source_ip."""
        safe_ip = _validate_source_ip(source_ip)
        if not safe_ip or not domain:
            return
        try:
            key = f"{{{safe_ip}}}:dns_domains"
            self.redis.sadd(key, domain)
            self.redis.expire(key, self.window_seconds)
            if self.redis.scard(key) > MAX_TRACKED_DOMAINS:
                self.redis.spop(key)
        except Exception as e:
            logger.error(f"DnsBehaviorTracker.record_query failed: {e}")

    def record_response(self, source_ip: str, is_nxdomain: bool) -> None:
        """Call once per DNS response seen for the client (source_ip is
        the querying client -- see ingest/pcap_ingester.py's
        _extract_dns_response_event(), which already resolves this from
        the response packet's destination, not its source)."""
        safe_ip = _validate_source_ip(source_ip)
        if not safe_ip:
            return
        try:
            total_key = f"{{{safe_ip}}}:dns_responses"
            pipe = self.redis.pipeline()
            pipe.incr(total_key)
            pipe.expire(total_key, self.window_seconds)
            if is_nxdomain:
                nx_key = f"{{{safe_ip}}}:dns_nxdomain"
                pipe.incr(nx_key)
                pipe.expire(nx_key, self.window_seconds)
            pipe.execute()
        except Exception as e:
            logger.error(f"DnsBehaviorTracker.record_response failed: {e}")

    def get_stats(self, source_ip: str) -> dict:
        """Returns {"distinct_domains", "nxdomain_rate", "total_responses"}
        for the current window. Fails closed (all zeros) on any Redis
        error or invalid IP -- a broken tracker degrades to "no burst
        detected," the same fail-open-on-error posture as
        DeepLearningEngine.predict() and FlowAnomalyEngine.score(),
        since a broken behavioral signal shouldn't itself become a
        denial-of-service on the rest of the pipeline."""
        safe_ip = _validate_source_ip(source_ip)
        if not safe_ip:
            return {"distinct_domains": 0, "nxdomain_rate": 0.0, "total_responses": 0}
        try:
            distinct_domains = self.redis.scard(f"{{{safe_ip}}}:dns_domains")
            total = int(self.redis.get(f"{{{safe_ip}}}:dns_responses") or 0)
            nx = int(self.redis.get(f"{{{safe_ip}}}:dns_nxdomain") or 0)
            nxdomain_rate = nx / total if total > 0 else 0.0
            return {"distinct_domains": distinct_domains, "nxdomain_rate": nxdomain_rate, "total_responses": total}
        except Exception as e:
            logger.error(f"DnsBehaviorTracker.get_stats failed: {e}")
            return {"distinct_domains": 0, "nxdomain_rate": 0.0, "total_responses": 0}

    def is_burst(self, source_ip: str):
        """Returns (is_burst: bool, reason: str or None, stats: dict).
        MIN_RESPONSES_FOR_NXDOMAIN_RATE guards against a single early
        NXDOMAIN looking like a 100% failure rate."""
        stats = self.get_stats(source_ip)
        if stats["distinct_domains"] >= DISTINCT_DOMAIN_BURST_THRESHOLD:
            return True, "distinct_domain_burst", stats
        if stats["total_responses"] >= MIN_RESPONSES_FOR_NXDOMAIN_RATE and stats["nxdomain_rate"] >= NXDOMAIN_RATE_THRESHOLD:
            return True, "high_nxdomain_rate", stats
        return False, None, stats
