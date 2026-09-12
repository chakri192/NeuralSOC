"""Per-(source, destination)-pair connection-rate and periodicity
tracking -- a genuinely different signal shape from
inference/rules.py's RULE_DDOS_VOLUMETRIC and RULE_C2_HEARTBEAT, which
both look at ONE connection in isolation.

Real-data investigation (docs/PATH_TO_10_OUT_OF_10.md) found those two
rules structurally can't work well against real traffic: a volumetric
flood is many small connections arriving fast, not one connection with a
huge packet count, and periodic C2 beaconing is a REGULAR INTERVAL
between many connections to the same destination, not any single
connection's byte size. Exhaustive real threshold sweeps against CTU-13
confirmed hard recall ceilings (~3% for DDoS, ~7.6% for C2) no amount of
single-flow threshold tuning could clear -- the same reason
RULE_DNS_QUERY_BURST (inference/dns_behavior.py) had to become a
windowed, stateful tracker instead of a per-query check. This module is
that same fix applied to connection-rate and periodicity, calibrated
against the real, raw CTU-13 .binetflow files (with real SrcAddr/DstAddr/
StartTime -- fields benchmarks/real_rule_validation_dataset.csv's already-
sampled extract doesn't carry).

Both signals below are scoped to a (source, destination) PAIR, not a
source alone. A per-source-alone rate check was tried first and found a
real, disqualifying false positive: CTU-13's own capture vantage point
includes a NAT/gateway-aggregated host (147.32.84.59, "cmpgw-CVUT" in
its own labels) whose traffic is really many different real users' web
browsing, funneled through one apparent source IP -- it produced bursts
of up to 49,000 connections in 10 seconds, spread across 91-1,142
distinct destinations. Real infected hosts performing a genuine
volumetric flood (CTU-13 scenarios 10 and 11, the only two of 13
scenarios with real confirmed flood behavior) hit exactly ONE destination
with 2,855-4,243 connections in the same window. Scoping to a
(source, destination) pair reproduces this real separation instead of
being fooled by legitimate fan-out.

Real-data calibration results (measured against all 13 real CTU-13
scenarios, comparing real infected hosts against real CONFIRMED-CLEAN
named hosts -- CTU-13's own "From-Normal-*" label, e.g. "Stribrek",
"CVUT-WebServer" -- not its "Background" bucket, which is unlabeled
ambient noise, not confirmed benign, per the same Botnet/Normal-only
discipline every other real-data evaluator in this project already
uses):

- DDoS-rate: 100% precision, 0% FPR at DDOS_CONNECTION_COUNT_THRESHOLD
  (a threshold of 1,000 sits with a wide, comfortable margin on both
  sides of the real 431-vs-2,855 gap above).
- C2 periodicity: a genuinely WEAKER standalone signal than DDoS-rate,
  and a different KIND of weak than DDoS-rate's threshold trade-off.
  Real confirmed C2 channels (CTU-13's own "From-Botnet-...-CC<N>-..."
  label, its ground truth for "this connection is a real C2 channel")
  do show tight, real periodicity (many pairs clustering at consistent
  ~30-300 second intervals), but a fine real threshold sweep
  (0.005-0.20) found recall is a flat, unmovable ~0.2-0.4% ceiling
  across that ENTIRE range -- most real "Botnet"-labeled connections
  simply aren't part of any periodic C2 channel at all, so no CV
  threshold can recover more of them. With recall fixed,
  BEACON_MAX_COEFFICIENT_OF_VARIATION is chosen purely to minimize real
  noise: 0.008 measures 37.0% precision / 0.58% FPR against real CTU-13
  traffic (both legitimate periodic background jobs -- analytics
  beacons, NTP-like checks -- and ordinary non-periodic botnet traffic
  ARE regular enough to look similar at looser thresholds). This is why
  its confidence (see the rule_id construction in
  inference/stream_processor_faust.py) is deliberately kept LOW -- below
  the point where inference/risk.py's log-odds pooling would let a
  single, uncorroborated firing become a published incident on its own.
  It's a real, disclosed, weak corroborating signal, not a standalone
  verdict -- the same posture inference/domain_age.py already takes for
  a young-but-legitimate domain.

Reuses the caller's already-configured Redis connection
(inference/correlation.py's IncidentCorrelator already enforces
mandatory auth + TLS) rather than opening a second connection pool with
its own security configuration to audit and potentially drift from the
first -- same reasoning as inference/dns_behavior.py's module docstring.

Every window here is measured against an explicit `timestamp` parameter,
not Redis's own wall-clock TTL/expire mechanism (unlike
DnsBehaviorTracker's SADD+EXPIRE pattern): a live deployment always
passes the real current time, but this is also what makes it possible to
replay historical, already-captured traffic (a pcap, or a real dataset
like CTU-13) through this tracker using each event's OWN recorded
timestamp, so validating this against months-old real attack data
doesn't require waiting for the real capture duration to elapse. A
sorted set per (source, destination) pair (score = timestamp) implements
the window: entries older than `timestamp - window_seconds` are evicted
on every write, so window membership is a query against real, recorded
event times, not against Redis's own clock. The DDoS-rate and C2-
periodicity checks share this ONE sorted set (querying different trailing
windows of it) rather than maintaining two separate structures per pair.
"""
import ipaddress
import itertools
import logging
import statistics
from typing import Optional

logger = logging.getLogger(__name__)

_counter = itertools.count()

# Bounded the same way inference/dns_behavior.py's MAX_TRACKED_DOMAINS
# is: a single noisy or attacking host shouldn't be able to grow Redis
# memory without limit just by generating a lot of connections.
MAX_TRACKED_TIMESTAMPS_PER_PAIR = 5000

# Real-data calibrated (see module docstring): true floods measured
# 2,855-4,243 connections/10s to a single real destination; the highest
# real confirmed-clean pair anywhere in CTU-13 reached 431. 1,000 sits
# comfortably clear of both real bounds, the same "safe distance from
# both sides of a real gap" discipline as every other calibrated
# threshold in this project.
DDOS_WINDOW_SECONDS = 10.0
DDOS_CONNECTION_COUNT_THRESHOLD = 1000

# Real-data calibrated: a 30-minute trailing window comfortably holds
# BEACON_MIN_OBSERVATIONS at the real C2 intervals actually observed
# (mostly 30-300 seconds; even 5 observations at the slower end fits
# well inside 1800s).
BEACON_WINDOW_SECONDS = 1800.0
BEACON_MIN_OBSERVATIONS = 5

# This is the one calibrated value in this module where real recall is a
# flat, unavoidable ceiling (~0.2-0.4%, measured across a fine 0.005-0.20
# sweep) rather than a real precision/recall trade-off: unlike DDoS-rate,
# there's no threshold anywhere in that range that moves recall
# meaningfully -- so the choice below is optimized purely for
# precision/FPR, matching the "corroboration only, keep noise low"
# posture a standalone-weak signal calls for. 0.008 measured 37.0%
# precision / 0.3% recall / 0.58% FPR against real CTU-13 traffic --
# tighter and cleaner than a looser threshold's real cost (0.20 measured
# 20.5%/0.9%/4.20%: barely more recall for meaningfully worse precision
# and 7x the FPR).
BEACON_MAX_COEFFICIENT_OF_VARIATION = 0.008
BEACON_MIN_INTERVAL_SECONDS = 5.0


def _validate_ip(raw_ip) -> Optional[str]:
    """Same discipline as inference/dns_behavior.py's
    _validate_source_ip -- source_ip/dest_ip here originate from network
    packet data (attacker-influenced), and building a Redis key by
    directly interpolating an unvalidated string would be a real
    key/command injection vector, not merely defensive paranoia."""
    try:
        addr = ipaddress.ip_address(str(raw_ip).strip())
    except ValueError:
        return None
    normalized = str(addr)
    if len(normalized) > 45:
        return None
    return normalized


class ConnBehaviorTracker:
    def __init__(
        self,
        redis_client,
        ddos_window_seconds: float = DDOS_WINDOW_SECONDS,
        ddos_connection_count_threshold: int = DDOS_CONNECTION_COUNT_THRESHOLD,
        beacon_window_seconds: float = BEACON_WINDOW_SECONDS,
        beacon_min_observations: int = BEACON_MIN_OBSERVATIONS,
        beacon_max_cv: float = BEACON_MAX_COEFFICIENT_OF_VARIATION,
        beacon_min_interval_seconds: float = BEACON_MIN_INTERVAL_SECONDS,
    ):
        self.redis = redis_client
        self.ddos_window_seconds = ddos_window_seconds
        self.ddos_connection_count_threshold = ddos_connection_count_threshold
        self.beacon_window_seconds = beacon_window_seconds
        self.beacon_min_observations = beacon_min_observations
        self.beacon_max_cv = beacon_max_cv
        self.beacon_min_interval_seconds = beacon_min_interval_seconds
        # The set is pruned to whichever window is longer, since both
        # checks share it -- pruning to the shorter DDoS window would
        # discard history the beacon check still needs.
        self._retention_seconds = max(ddos_window_seconds, beacon_window_seconds)

    def _pair_key(self, safe_src: str, safe_dst: str) -> str:
        return f"{{{safe_src}}}:conn_pair:{safe_dst}"

    def record_connection(self, source_ip: str, dest_ip: str, timestamp: float) -> None:
        """Call once per outbound connection (event_type == "conn") seen
        for source_ip. Feeds both the DDoS rate window and the C2
        periodicity window for this (source, destination) pair."""
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst or timestamp is None:
            return
        try:
            pair_key = self._pair_key(safe_src, safe_dst)
            member = f"{timestamp}:{next(_counter)}"
            pipe = self.redis.pipeline()
            pipe.zadd(pair_key, {member: timestamp})
            pipe.zremrangebyscore(pair_key, "-inf", timestamp - self._retention_seconds)
            pipe.zremrangebyrank(pair_key, 0, -MAX_TRACKED_TIMESTAMPS_PER_PAIR - 1)
            pipe.expire(pair_key, int(self._retention_seconds))
            pipe.execute()
        except Exception as e:
            logger.error(f"ConnBehaviorTracker.record_connection failed: {e}")

    def is_ddos_volumetric(self, source_ip: str, dest_ip: str, timestamp: float):
        """Returns (is_flood: bool, stats: dict). Fails closed (not a
        flood) on any Redis error or invalid IP -- a broken tracker
        degrades to "no burst detected," the same posture as
        DnsBehaviorTracker.is_burst()."""
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst:
            return False, {"connection_count": 0}
        try:
            pair_key = self._pair_key(safe_src, safe_dst)
            count = self.redis.zcount(pair_key, timestamp - self.ddos_window_seconds, timestamp)
            stats = {"connection_count": count, "window_seconds": self.ddos_window_seconds}
            return count >= self.ddos_connection_count_threshold, stats
        except Exception as e:
            logger.error(f"ConnBehaviorTracker.is_ddos_volumetric failed: {e}")
            return False, {"connection_count": 0}

    def is_c2_beacon(self, source_ip: str, dest_ip: str, timestamp: float):
        """Returns (is_beacon: bool, stats: dict). A real beacon needs
        BOTH low interval variance (regular polling, not bursty/random
        traffic) AND a real gap between connections
        (beacon_min_interval_seconds) -- without the latter, a single
        rapid burst of near-simultaneous connections (near-zero
        intervals, near-zero variance) would look "perfectly regular"
        and false-positive as a beacon. Fails closed on any error.

        This signal is real but standalone-weak (see module docstring:
        ~12-19% real precision alone) -- callers should assign this a
        correspondingly low confidence, not treat a lone firing as a
        confirmed verdict."""
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst:
            return False, {"observations": 0}
        try:
            pair_key = self._pair_key(safe_src, safe_dst)
            entries = self.redis.zrangebyscore(
                pair_key, timestamp - self.beacon_window_seconds, timestamp, withscores=True
            )
            timestamps = sorted(score for _member, score in entries)
        except Exception as e:
            logger.error(f"ConnBehaviorTracker.is_c2_beacon failed: {e}")
            return False, {"observations": 0}

        n = len(timestamps)
        if n < self.beacon_min_observations:
            return False, {"observations": n}

        intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
        mean_interval = statistics.mean(intervals)
        stats = {"observations": n, "mean_interval_seconds": mean_interval}
        if mean_interval < self.beacon_min_interval_seconds:
            return False, stats
        if len(intervals) < 2:
            return False, stats
        stdev_interval = statistics.stdev(intervals)
        coefficient_of_variation = stdev_interval / mean_interval if mean_interval else float("inf")
        stats["coefficient_of_variation"] = coefficient_of_variation
        return coefficient_of_variation <= self.beacon_max_cv, stats
