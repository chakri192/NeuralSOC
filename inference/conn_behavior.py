"""Per-(source, destination)-pair connection-rate, periodicity, and
byte-volume tracking -- a genuinely different signal shape from
inference/rules.py's RULE_DDOS_VOLUMETRIC, RULE_C2_HEARTBEAT, and
RULE_CONN_EXFIL, which all look at ONE connection in isolation.

Real-data investigation (docs/PATH_TO_10_OUT_OF_10.md) found those three
rules structurally can't work well against real traffic: a volumetric
flood is many small connections arriving fast, not one connection with a
huge packet count; periodic C2 beaconing is a REGULAR INTERVAL between
many connections to the same destination, not any single connection's
byte size; and bulk exfiltration is real total bytes moved to one
destination OVER TIME, not necessarily any single connection's own byte
count. Exhaustive real threshold sweeps against CTU-13 confirmed hard
recall ceilings (~3% for DDoS, ~7.6% for C2, ~1.5% for exfil) no amount
of single-flow threshold tuning could clear -- the same reason
RULE_DNS_QUERY_BURST (inference/dns_behavior.py) had to become a
windowed, stateful tracker instead of a per-query check. This module is
that same fix applied to connection-rate, periodicity, and byte volume,
calibrated against the real, raw CTU-13 .binetflow files (with real
SrcAddr/DstAddr/StartTime -- fields
benchmarks/real_rule_validation_dataset.csv's already-sampled extract
doesn't carry).

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
  do show tight, real periodicity (some pairs measure a coefficient of
  variation as low as 0.0009), but real intervals are often 30-90+
  minutes -- an original fine threshold sweep (0.005-0.20) found a flat
  ~0.2-0.4% recall ceiling across that whole range, which turned out to
  be a WINDOW-SIZE problem, not a CV-threshold one: the old 1800s (30
  minute) window structurally could never accumulate enough observations
  at those real intervals, so no CV threshold could have recovered them.
  Widened BEACON_WINDOW_SECONDS to 21600s (6 hours) and lowered
  BEACON_MIN_OBSERVATIONS to 3 to fix that directly, then re-swept CV
  past the original 0.20 ceiling and found the real trade-off curve
  doesn't cliff until beyond 0.9: BEACON_MAX_COEFFICIENT_OF_VARIATION=0.5
  measures 65.7% precision / 2.92% recall / 1.91% FPR against real
  CTU-13 traffic -- an ~11x real recall improvement over the original
  0.008 (37.0%/0.27%/0.58%) that ALSO improves precision, not a
  precision-for-recall trade-off (0.008 was simply too strict on both
  axes, chosen before the window-size root cause was known). Even at
  2.92% recall this is still a genuinely weaker standalone signal than
  DDoS-rate or bulk exfiltration below -- most real "Botnet"-labeled
  connections still aren't part of any periodic C2 channel at all. This
  is why its confidence (see the rule_id construction in
  inference/stream_processor_faust.py) is deliberately kept LOW -- below
  the point where inference/risk.py's log-odds pooling would let a
  single, uncorroborated firing become a published incident on its own.
  It's a real, disclosed, weak corroborating signal, not a standalone
  verdict -- the same posture inference/domain_age.py already takes for
  a young-but-legitimate domain.
- Bulk exfiltration: a clean, strong signal, the same real "many small
  events add up to one attack" shape as DDoS-rate. Summing orig_bytes
  per (source, destination) pair over EXFIL_WINDOW_SECONDS instead of
  checking any one connection's own byte count: EXFIL_BYTES_THRESHOLD
  (1,000,000) measures 100% precision / 22.2% recall / 0.008% FPR --
  roughly 74x the single-flow rule's real recall (~0.3%), at higher
  precision and comparably negligible FPR.

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
event times, not against Redis's own clock. All three checks share this
ONE sorted set (querying different trailing windows of it, and for
bulk-exfil, summing a byte count encoded into each member) rather than
maintaining three separate structures per pair.
"""
import ipaddress
import itertools
import logging
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

# Real-data root cause (found while chasing this rule's flat recall
# ceiling below): a direct inter-arrival-time analysis of every real
# CTU-13 Botnet-labeled (source, destination) pair found genuinely
# near-perfect periodic beaconing DOES exist in the ground truth (some
# pairs measure a coefficient of variation as low as 0.0009), but at
# real intervals often in the 30-90+ minute range -- structurally unable
# to ever accumulate BEACON_MIN_OBSERVATIONS within the old 1800s (30
# minute) window, no matter how loose BEACON_MAX_COEFFICIENT_OF_VARIATION
# was set. This was a window-size miscalibration, not an algorithmic
# weakness: the old window was simply too short for real C2 cadences.
# Widened to 21600s (6 hours) -- comfortably holds 3+ observations even
# at hour-long real intervals -- and BEACON_MIN_OBSERVATIONS lowered to
# 3 (a real beacon relationship interrupted by one off-cadence connection
# would otherwise need 5 CONSECUTIVE clean intervals within the window to
# ever qualify, which real, imperfect traffic often doesn't provide).
# Retention cost: ConnBehaviorTracker._retention_seconds is the max of
# all three window sizes, so this is now also the real memory-retention
# window per (source, destination) pair (still bounded by
# MAX_TRACKED_TIMESTAMPS_PER_PAIR).
BEACON_WINDOW_SECONDS = 21600.0
BEACON_MIN_OBSERVATIONS = 3

# The original fine sweep here only ever tested 0.005-0.20 and found a
# flat ~0.2-0.4% recall ceiling across that whole range -- true, but an
# artifact of never testing higher: most real "Botnet"-labeled
# connections genuinely aren't part of ANY periodic C2 channel (confirmed
# again after the window fix above -- recall is still capped under 1%
# for any threshold under ~0.3), but a real, substantial LOOSER-than-
# textbook-jitter-tolerance population does exist and was being missed
# entirely. A sweep extended up to 1.5 found the real trade-off curve
# doesn't cliff until >0.9 (FPR jumps from ~2% to ~9%+); 0.5 was chosen
# as the value that respects this project's own <2% FPR ceiling for this
# detector while still delivering the large majority of the achievable
# gain: measured (real CTU-13, all 13 scenarios) 65.7% precision / 2.92%
# recall / 1.91% FPR -- versus the old 0.008's 37.0%/0.27%/0.58%, an
# ~11x real recall improvement that ALSO improves precision, not a
# precision-for-recall trade. (0.008 was too strict on both axes at
# once, not a considered trade-off point -- it was chosen before the
# window-size problem above was known to exist.)
BEACON_MAX_COEFFICIENT_OF_VARIATION = 0.5
BEACON_MIN_INTERVAL_SECONDS = 5.0

# Real-data calibrated: the existing single-flow RULE_CONN_EXFIL (one
# connection's own orig_bytes > 5,000,000) measured only ~1.5% recall at
# any real threshold sweep -- bulk exfiltration in real traffic is
# rarely one giant flow, it's the SAME total moved across many smaller
# ones over time, the same "many small events, not one big one" shape
# DDoS-rate already fixed for floods. Summing orig_bytes per
# (source, destination) pair over a real 10-minute trailing window finds
# it: 1,000,000 bytes measured 100% precision / 22.2% recall / 0.008%
# FPR against real CTU-13 traffic -- roughly 74x the single-flow rule's
# real recall, at higher precision and comparably negligible FPR.
EXFIL_WINDOW_SECONDS = 600.0
EXFIL_BYTES_THRESHOLD = 1_000_000.0


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
        exfil_window_seconds: float = EXFIL_WINDOW_SECONDS,
        exfil_bytes_threshold: float = EXFIL_BYTES_THRESHOLD,
    ):
        self.redis = redis_client
        self.ddos_window_seconds = ddos_window_seconds
        self.ddos_connection_count_threshold = ddos_connection_count_threshold
        self.beacon_window_seconds = beacon_window_seconds
        self.beacon_min_observations = beacon_min_observations
        self.beacon_max_cv = beacon_max_cv
        self.beacon_min_interval_seconds = beacon_min_interval_seconds
        self.exfil_window_seconds = exfil_window_seconds
        self.exfil_bytes_threshold = exfil_bytes_threshold
        # The set is pruned to whichever window is longest, since all
        # three checks share it -- pruning to a shorter window would
        # discard history a longer-window check still needs.
        self._retention_seconds = max(ddos_window_seconds, beacon_window_seconds, exfil_window_seconds)

    def _pair_key(self, safe_src: str, safe_dst: str) -> str:
        return f"{{{safe_src}}}:conn_pair:{safe_dst}"

    def record_connection(self, source_ip: str, dest_ip: str, timestamp: float, orig_bytes: float = 0.0) -> None:
        """Call once per outbound connection (event_type == "conn") seen
        for source_ip. Feeds the DDoS rate window, the C2 periodicity
        window, and the bulk-exfil byte-sum window, all for this
        (source, destination) pair. orig_bytes is encoded into the
        sorted-set member itself (score stays the timestamp, so time-
        range queries are unaffected) -- the simplest way to let
        is_bulk_exfil() recover each entry's byte count without a
        second data structure to keep in sync."""
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst or timestamp is None:
            return
        try:
            safe_bytes = max(0.0, float(orig_bytes))
        except (TypeError, ValueError):
            safe_bytes = 0.0
        try:
            pair_key = self._pair_key(safe_src, safe_dst)
            member = f"{timestamp}:{next(_counter)}:{safe_bytes}"
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

        This signal is real but standalone-weak (see module docstring)
        -- callers should assign this a correspondingly low confidence,
        not treat a lone firing as a confirmed verdict."""
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
        n_intervals = len(intervals)
        # Plain-float mean/sample-stdev instead of statistics.mean()/stdev()
        # -- mathematically identical (verified to ~1e-14 floating-point
        # precision, immaterial for a threshold comparison), but avoids
        # the statistics module's internal exact-Fraction arithmetic,
        # which is measurably slow when recomputed on every single
        # connection event for a busy (source, destination) pair (up to
        # MAX_TRACKED_TIMESTAMPS_PER_PAIR=5000 entries) -- a real cost
        # that matters more now that BEACON_WINDOW_SECONDS is wide enough
        # for busy pairs to actually approach that cap.
        mean_interval = sum(intervals) / n_intervals
        stats = {"observations": n, "mean_interval_seconds": mean_interval}
        if mean_interval < self.beacon_min_interval_seconds:
            return False, stats
        if n_intervals < 2:
            return False, stats
        variance = sum((x - mean_interval) ** 2 for x in intervals) / (n_intervals - 1)
        stdev_interval = variance ** 0.5
        coefficient_of_variation = stdev_interval / mean_interval if mean_interval else float("inf")
        stats["coefficient_of_variation"] = coefficient_of_variation
        return coefficient_of_variation <= self.beacon_max_cv, stats

    def is_bulk_exfil(self, source_ip: str, dest_ip: str, timestamp: float):
        """Returns (is_exfil: bool, stats: dict). Sums orig_bytes across
        every connection in the window instead of looking at any one
        connection alone -- the real fix for the same "many small events
        add up to one big pattern" shape is_ddos_volumetric() already
        handles for connection counts, applied to bytes moved instead.
        Fails closed on any error."""
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst:
            return False, {"total_bytes": 0.0}
        try:
            pair_key = self._pair_key(safe_src, safe_dst)
            members = self.redis.zrangebyscore(pair_key, timestamp - self.exfil_window_seconds, timestamp)
            total_bytes = 0.0
            for member in members:
                try:
                    # A Redis client configured for decode_responses=True
                    # should always hand back str, but this defends
                    # against a client (or client-mocking interaction, as
                    # found in this project's own test suite) that
                    # returns bytes instead -- bytes.rsplit() requires a
                    # bytes separator, not the str one used below.
                    if isinstance(member, bytes):
                        member = member.decode("utf-8", errors="ignore")
                    total_bytes += float(member.rsplit(":", 1)[1])
                except (IndexError, ValueError):
                    continue
            stats = {"total_bytes": total_bytes, "window_seconds": self.exfil_window_seconds}
            return total_bytes >= self.exfil_bytes_threshold, stats
        except Exception as e:
            logger.error(f"ConnBehaviorTracker.is_bulk_exfil failed: {e}")
            return False, {"total_bytes": 0.0}
