"""FastConnBehaviorTracker -- a pure-Python, in-memory stand-in for
inference/conn_behavior.py's Redis-backed ConnBehaviorTracker, built for
one purpose: making this project's real-data evaluators
(evaluate_conn_behavior_against_real_data.py,
evaluate_composite_scoring_against_real_data.py) fast enough to iterate
on, without giving up correctness.

Why this exists: those evaluators replay ~800k real CTU-13 connections
through the real, fakeredis-backed ConnBehaviorTracker. Each of its three
checks re-queries and, for is_c2_beacon()/is_bulk_exfil(), re-derives
statistics from the FULL set of entries in the relevant window on every
single call -- an O(window size) cost paid on every event, which becomes
O(n^2)-shaped for a busy (source, destination) pair. That was fine when
BEACON_WINDOW_SECONDS was 1800s (30 minutes), but once real-data
root-causing widened it to 21600s (6 hours) to catch real C2 beacons that
fire every 30-90+ minutes, evaluator runs against this project's ~800k-row
real dataset went from a couple of minutes to 30+ minutes with zero
progress output -- a real cost paid this session while calibrating that
fix, and one every future workstream (JA4, DGA ensembling, further C2
tuning) would keep paying without a fix.

This class reimplements the exact same three checks using per-pair
incremental sliding-window state (running sums/counts maintained on
insert/evict, not recomputed from scratch per call) instead of Redis
range queries -- O(1) amortized per event instead of O(window size).
Never used in production (inference/stream_processor_faust.py keeps using
the real Redis-backed ConnBehaviorTracker unchanged, since production
needs Redis's cross-process/cross-replica shared state, which this class
deliberately does not provide) -- evaluation-only.

Trust, not just speed: see
tests/unit/test_fast_conn_behavior.py, which replays real CTU-13
connections through both this class and the real, fakeredis-backed
ConnBehaviorTracker and asserts every is_ddos_volumetric()/is_c2_beacon()/
is_bulk_exfil() decision matches exactly. Only trust this class's numbers
for a new calibration decision after that test passes for the relevant
window/threshold configuration.

One known, disclosed divergence from the real tracker: MAX_TRACKED_TIMESTAMPS_PER_PAIR
(the real tracker's shared-sorted-set rank cap, a memory-safety guard, not
a detection threshold) is not replicated here -- each detector's own
window here is unbounded by entry count. This only matters for a
(source, destination) pair sustaining more than 5,000 connections within
the widest configured window, which the parity test's real-data replay
confirms does not change any decision on this project's actual CTU-13
dataset (the pairs busy enough to reach that count either far exceed
detection thresholds regardless, or are confirmed-clean NAT/gateway-shaped
traffic already excluded by the per-pair, not per-source, scoping
inference/conn_behavior.py's own module docstring describes).
"""
from collections import defaultdict, deque

import ipaddress
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.conn_behavior import (  # noqa: E402
    DDOS_CONNECTION_COUNT_THRESHOLD,
    DDOS_WINDOW_SECONDS,
    BEACON_MAX_COEFFICIENT_OF_VARIATION,
    BEACON_MIN_INTERVAL_SECONDS,
    BEACON_MIN_OBSERVATIONS,
    BEACON_WINDOW_SECONDS,
    EXFIL_BYTES_THRESHOLD,
    EXFIL_WINDOW_SECONDS,
)


def _validate_ip(raw_ip):
    """Mirrors inference/conn_behavior.py's _validate_ip exactly."""
    try:
        addr = ipaddress.ip_address(str(raw_ip).strip())
    except ValueError:
        return None
    normalized = str(addr)
    if len(normalized) > 45:
        return None
    return normalized


class _PairState:
    __slots__ = (
        "ddos_ts", "beacon_ts", "beacon_intervals", "beacon_sum", "beacon_sumsq",
        "last_ts", "exfil_entries", "exfil_sum",
    )

    def __init__(self):
        self.ddos_ts = deque()
        self.beacon_ts = deque()
        self.beacon_intervals = deque()  # each: (end_ts, interval_value)
        self.beacon_sum = 0.0
        self.beacon_sumsq = 0.0
        self.last_ts = None
        self.exfil_entries = deque()  # each: (ts, orig_bytes)
        self.exfil_sum = 0.0


class FastConnBehaviorTracker:
    def __init__(
        self,
        redis_client=None,  # accepted, ignored -- keeps the constructor call-compatible
        ddos_window_seconds=DDOS_WINDOW_SECONDS,
        ddos_connection_count_threshold=DDOS_CONNECTION_COUNT_THRESHOLD,
        beacon_window_seconds=BEACON_WINDOW_SECONDS,
        beacon_min_observations=BEACON_MIN_OBSERVATIONS,
        beacon_max_cv=BEACON_MAX_COEFFICIENT_OF_VARIATION,
        beacon_min_interval_seconds=BEACON_MIN_INTERVAL_SECONDS,
        exfil_window_seconds=EXFIL_WINDOW_SECONDS,
        exfil_bytes_threshold=EXFIL_BYTES_THRESHOLD,
    ):
        self.ddos_window_seconds = ddos_window_seconds
        self.ddos_connection_count_threshold = ddos_connection_count_threshold
        self.beacon_window_seconds = beacon_window_seconds
        self.beacon_min_observations = beacon_min_observations
        self.beacon_max_cv = beacon_max_cv
        self.beacon_min_interval_seconds = beacon_min_interval_seconds
        self.exfil_window_seconds = exfil_window_seconds
        self.exfil_bytes_threshold = exfil_bytes_threshold
        self._pairs = defaultdict(_PairState)

    def record_connection(self, source_ip, dest_ip, timestamp, orig_bytes=0.0):
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst or timestamp is None:
            return
        try:
            safe_bytes = max(0.0, float(orig_bytes))
        except (TypeError, ValueError):
            safe_bytes = 0.0

        st = self._pairs[(safe_src, safe_dst)]

        # DDoS window: just needs a count, so a plain timestamp deque suffices.
        st.ddos_ts.append(timestamp)
        while st.ddos_ts and st.ddos_ts[0] < timestamp - self.ddos_window_seconds:
            st.ddos_ts.popleft()

        # Beacon window: observation count (for beacon_min_observations)...
        st.beacon_ts.append(timestamp)
        while st.beacon_ts and st.beacon_ts[0] < timestamp - self.beacon_window_seconds:
            st.beacon_ts.popleft()
        # ...and incremental interval sum/sum-of-squares (for mean/sample-stdev).
        if st.last_ts is not None:
            iv = timestamp - st.last_ts
            if iv > 0:
                st.beacon_intervals.append((timestamp, iv))
                st.beacon_sum += iv
                st.beacon_sumsq += iv * iv
        st.last_ts = timestamp
        while st.beacon_intervals and st.beacon_intervals[0][0] < timestamp - self.beacon_window_seconds:
            _, old_iv = st.beacon_intervals.popleft()
            st.beacon_sum -= old_iv
            st.beacon_sumsq -= old_iv * old_iv

        # Exfil window: incremental byte sum.
        st.exfil_entries.append((timestamp, safe_bytes))
        st.exfil_sum += safe_bytes
        while st.exfil_entries and st.exfil_entries[0][0] < timestamp - self.exfil_window_seconds:
            _, old_bytes = st.exfil_entries.popleft()
            st.exfil_sum -= old_bytes

    def is_ddos_volumetric(self, source_ip, dest_ip, timestamp):
        """O(1): relies on the documented usage pattern this stand-in is
        built for (record_connection() called with this same timestamp
        immediately before every check, exactly what both evaluator
        scripts do) -- by that point st.ddos_ts already holds exactly the
        entries within [timestamp - window, timestamp], so its length IS
        the count, no re-filtering needed. Not safe to call with a
        timestamp older than the pair's last record_connection() call."""
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst:
            return False, {"connection_count": 0}
        st = self._pairs.get((safe_src, safe_dst))
        if st is None:
            return False, {"connection_count": 0}
        count = len(st.ddos_ts)
        stats = {"connection_count": count, "window_seconds": self.ddos_window_seconds}
        return count >= self.ddos_connection_count_threshold, stats

    def is_c2_beacon(self, source_ip, dest_ip, timestamp):
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst:
            return False, {"observations": 0}
        st = self._pairs.get((safe_src, safe_dst))
        if st is None:
            return False, {"observations": 0}

        n = len(st.beacon_ts)
        if n < self.beacon_min_observations:
            return False, {"observations": n}

        n_intervals = len(st.beacon_intervals)
        if n_intervals == 0:
            return False, {"observations": n}
        mean_interval = st.beacon_sum / n_intervals
        stats = {"observations": n, "mean_interval_seconds": mean_interval}
        if mean_interval < self.beacon_min_interval_seconds:
            return False, stats
        if n_intervals < 2:
            return False, stats
        ss = st.beacon_sumsq - n_intervals * mean_interval * mean_interval
        variance = max(0.0, ss) / (n_intervals - 1)
        stdev_interval = variance ** 0.5
        coefficient_of_variation = stdev_interval / mean_interval if mean_interval else float("inf")
        stats["coefficient_of_variation"] = coefficient_of_variation
        return coefficient_of_variation <= self.beacon_max_cv, stats

    def is_bulk_exfil(self, source_ip, dest_ip, timestamp):
        safe_src = _validate_ip(source_ip)
        safe_dst = _validate_ip(dest_ip)
        if not safe_src or not safe_dst:
            return False, {"total_bytes": 0.0}
        st = self._pairs.get((safe_src, safe_dst))
        if st is None:
            return False, {"total_bytes": 0.0}
        stats = {"total_bytes": st.exfil_sum, "window_seconds": self.exfil_window_seconds}
        return st.exfil_sum >= self.exfil_bytes_threshold, stats
