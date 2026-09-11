"""DnsBehaviorTracker tracks per-source-host DNS query/response behavior
(distinct-domain bursts, NXDOMAIN rate) as a complement to the DGA CNN's
per-domain character classification -- see inference/dns_behavior.py's
module docstring for why this signal matters. fakeredis (already a test
dependency for inference/correlation.py's own tests) exercises the real
Redis command sequences (SADD/EXPIRE/SCARD/INCR/pipeline) rather than
mocking them away.
"""
import os
import random
from unittest.mock import MagicMock

import fakeredis
import pytest

from inference.dns_behavior import (
    DISTINCT_DOMAIN_BURST_THRESHOLD,
    MAX_TRACKED_DOMAINS,
    MIN_RESPONSES_FOR_NXDOMAIN_RATE,
    DnsBehaviorTracker,
    _validate_source_ip,
)

_REAL_BENIGN_DOMAINS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "benchmarks", "real_benign_domains_train.csv"
)


@pytest.fixture
def tracker():
    # An explicit, per-test FakeServer -- fakeredis.FakeRedis() instances
    # constructed without one share a default global backing store keyed
    # by (host, port), which silently leaked state (and burst flags)
    # across these tests the first time this was written.
    server = fakeredis.FakeServer()
    return DnsBehaviorTracker(fakeredis.FakeRedis(server=server, decode_responses=True), window_seconds=60)


class TestValidateSourceIp:
    def test_accepts_valid_ipv4(self):
        assert _validate_source_ip("10.0.0.5") == "10.0.0.5"

    def test_accepts_valid_ipv6(self):
        assert _validate_source_ip("::1") == "::1"

    def test_rejects_non_ip_garbage(self):
        assert _validate_source_ip("not-an-ip") is None

    def test_rejects_redis_key_injection_attempt(self):
        # A string like this, if interpolated directly into an f-string
        # key, would let a crafted "source_ip" from a packet reach past
        # the intended hash-tag boundary into a second, attacker-chosen
        # key -- ipaddress.ip_address() rejects it outright instead.
        assert _validate_source_ip("10.0.0.5}:evil_key{") is None


class TestRecordQuery:
    def test_distinct_domains_are_counted(self, tracker):
        tracker.record_query("10.0.0.5", "a.com")
        tracker.record_query("10.0.0.5", "b.com")
        tracker.record_query("10.0.0.5", "a.com")  # duplicate, not double-counted
        stats = tracker.get_stats("10.0.0.5")
        assert stats["distinct_domains"] == 2

    def test_different_source_ips_are_isolated(self, tracker):
        tracker.record_query("10.0.0.5", "a.com")
        tracker.record_query("10.0.0.6", "b.com")
        tracker.record_query("10.0.0.6", "c.com")
        assert tracker.get_stats("10.0.0.5")["distinct_domains"] == 1
        assert tracker.get_stats("10.0.0.6")["distinct_domains"] == 2

    def test_domain_count_is_bounded(self, tracker):
        for i in range(MAX_TRACKED_DOMAINS + 50):
            tracker.record_query("10.0.0.5", f"domain{i}.com")
        assert tracker.get_stats("10.0.0.5")["distinct_domains"] <= MAX_TRACKED_DOMAINS

    def test_invalid_source_ip_is_silently_ignored(self, tracker):
        tracker.record_query("not-an-ip", "a.com")  # must not raise
        assert tracker.get_stats("not-an-ip") == {"distinct_domains": 0, "nxdomain_rate": 0.0, "total_responses": 0}

    def test_empty_domain_is_ignored(self, tracker):
        tracker.record_query("10.0.0.5", "")
        assert tracker.get_stats("10.0.0.5")["distinct_domains"] == 0

    def test_redis_error_is_logged_not_raised(self):
        broken_redis = MagicMock()
        broken_redis.sadd.side_effect = RuntimeError("redis down")
        tracker = DnsBehaviorTracker(broken_redis)
        tracker.record_query("10.0.0.5", "a.com")  # must not raise


class TestRecordResponse:
    def test_nxdomain_rate_is_computed(self, tracker):
        for _ in range(3):
            tracker.record_response("10.0.0.5", is_nxdomain=True)
        for _ in range(2):
            tracker.record_response("10.0.0.5", is_nxdomain=False)
        stats = tracker.get_stats("10.0.0.5")
        assert stats["total_responses"] == 5
        assert stats["nxdomain_rate"] == pytest.approx(0.6)

    def test_no_responses_yields_zero_rate_not_division_error(self, tracker):
        stats = tracker.get_stats("10.0.0.5")
        assert stats["total_responses"] == 0
        assert stats["nxdomain_rate"] == 0.0

    def test_redis_error_is_logged_not_raised(self):
        broken_redis = MagicMock()
        broken_redis.pipeline.side_effect = RuntimeError("redis down")
        tracker = DnsBehaviorTracker(broken_redis)
        tracker.record_response("10.0.0.5", is_nxdomain=True)  # must not raise


class TestIsBurst:
    def test_flags_distinct_domain_burst(self, tracker):
        for i in range(DISTINCT_DOMAIN_BURST_THRESHOLD):
            tracker.record_query("10.0.0.5", f"random{i}.com")
        is_burst, reason, stats = tracker.is_burst("10.0.0.5")
        assert is_burst is True
        assert reason == "distinct_domain_burst"

    def test_flags_high_nxdomain_rate_once_enough_responses_seen(self, tracker):
        for _ in range(MIN_RESPONSES_FOR_NXDOMAIN_RATE):
            tracker.record_response("10.0.0.5", is_nxdomain=True)
        is_burst, reason, stats = tracker.is_burst("10.0.0.5")
        assert is_burst is True
        assert reason == "high_nxdomain_rate"

    def test_a_single_early_nxdomain_does_not_trigger_burst(self, tracker):
        # MIN_RESPONSES_FOR_NXDOMAIN_RATE guard: 1/1 = 100% NXDOMAIN rate
        # but far too little data to act on.
        tracker.record_response("10.0.0.5", is_nxdomain=True)
        is_burst, reason, stats = tracker.is_burst("10.0.0.5")
        assert is_burst is False
        assert stats["nxdomain_rate"] == 1.0

    def test_ordinary_browsing_does_not_trigger_burst(self, tracker):
        tracker.record_query("10.0.0.5", "google.com")
        tracker.record_response("10.0.0.5", is_nxdomain=False)
        is_burst, reason, stats = tracker.is_burst("10.0.0.5")
        assert is_burst is False
        assert reason is None

    def test_small_sample_high_rate_no_longer_false_positives(self, tracker):
        """Regression test: MIN_RESPONSES_FOR_NXDOMAIN_RATE was
        originally 5 -- a plausible benign scenario (a VPN client
        failing to resolve 3 internal hostnames while disconnected,
        alongside 3 ordinary lookups that resolve fine) hit exactly a
        50% rate at 6 total responses and false-triggered. Real live
        pipeline data showed the genuine detections this threshold
        exists to catch mostly fire with 9+ responses anyway (only 8 of
        many real alerts fired at the old 5-7 response minimum), so
        raising it costs only the least statistically confident early
        alerts, not real detection capability."""
        for _ in range(3):
            tracker.record_response("10.0.0.5", is_nxdomain=False)
        for _ in range(3):
            tracker.record_response("10.0.0.5", is_nxdomain=True)
        is_burst, reason, stats = tracker.is_burst("10.0.0.5")
        assert stats["nxdomain_rate"] == 0.5
        assert stats["total_responses"] == 6
        assert is_burst is False

    def test_get_stats_error_degrades_to_not_a_burst(self):
        broken_redis = MagicMock()
        broken_redis.scard.side_effect = RuntimeError("redis down")
        broken_redis.get.side_effect = RuntimeError("redis down")
        tracker = DnsBehaviorTracker(broken_redis)
        is_burst, reason, stats = tracker.is_burst("10.0.0.5")  # must not raise
        assert is_burst is False


class TestRealBenignBurstDoesNotFalsePositive:
    """DISTINCT_DOMAIN_BURST_THRESHOLD was originally 15 and false-
    positived 100% of the time (200/200 simulated trials) on a single
    host querying just 15 random REAL domains in a tight window -- a
    volume any moderately heavy page load or multi-tab browsing session
    can hit. This is the regression test for that fix: real domains from
    benchmarks/real_benign_domains_train.csv (the same corpus the DGA
    model trains its benign side on), fed through the real tracker, must
    not trigger a burst at realistic browsing volumes.
    """

    @pytest.fixture(scope="class")
    def real_domains(self):
        with open(_REAL_BENIGN_DOMAINS_PATH, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _simulate_burst(self, real_domains, n_domains, seed):
        rng = random.Random(seed)  # nosec B311
        server = fakeredis.FakeServer()
        tracker = DnsBehaviorTracker(fakeredis.FakeRedis(server=server, decode_responses=True), window_seconds=60)
        host = "10.0.0.1"
        for domain in rng.sample(real_domains, n_domains):
            tracker.record_query(host, domain)
            tracker.record_response(host, is_nxdomain=False)  # realistic: legit lookups resolve
        return tracker.is_burst(host)

    @pytest.mark.parametrize("n_domains", [10, 20, 30, DISTINCT_DOMAIN_BURST_THRESHOLD - 1])
    def test_realistic_browsing_burst_sizes_never_false_positive(self, real_domains, n_domains):
        for seed in range(20):  # multiple real random samples, not just one lucky draw
            is_burst, reason, stats = self._simulate_burst(real_domains, n_domains, seed)
            assert not is_burst, f"seed={seed} n={n_domains} falsely flagged: {stats} ({reason})"

    def test_volume_at_or_above_threshold_still_flags(self, real_domains):
        is_burst, reason, stats = self._simulate_burst(real_domains, DISTINCT_DOMAIN_BURST_THRESHOLD, seed=0)
        assert is_burst is True
        assert reason == "distinct_domain_burst"
