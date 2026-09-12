"""ConnBehaviorTracker tracks per-(source, destination)-pair connection
rate (DDoS-shaped floods) and periodicity (C2-shaped beaconing) -- see
inference/conn_behavior.py's module docstring for why single-flow rules
structurally can't see either pattern, and why both checks are scoped to
a pair rather than a source alone (a real, disqualifying false-positive
mode found during real-data calibration: a NAT/gateway-aggregated host
produces huge connection bursts spread across many distinct
destinations, which a per-source-alone check can't tell apart from a
real flood at one destination). fakeredis exercises the real Redis
command sequences (ZADD/ZREMRANGEBYSCORE/ZCOUNT/ZRANGEBYSCORE/pipeline),
matching tests/unit/test_dns_behavior.py's own approach.
"""
from unittest.mock import MagicMock

import fakeredis
import pytest

from inference.conn_behavior import ConnBehaviorTracker, _validate_ip


@pytest.fixture
def tracker():
    # An explicit, per-test FakeServer -- see test_dns_behavior.py's own
    # fixture comment for why (FakeRedis() without one shares a global
    # backing store across instances).
    server = fakeredis.FakeServer()
    return ConnBehaviorTracker(
        fakeredis.FakeRedis(server=server, decode_responses=True),
        ddos_window_seconds=10.0,
        ddos_connection_count_threshold=1000,
        beacon_window_seconds=1800.0,
        beacon_min_observations=5,
        beacon_max_cv=0.20,
        beacon_min_interval_seconds=5.0,
    )


class TestValidateIp:
    def test_accepts_valid_ipv4(self):
        assert _validate_ip("10.0.0.5") == "10.0.0.5"

    def test_rejects_non_ip_garbage(self):
        assert _validate_ip("not-an-ip") is None

    def test_rejects_redis_key_injection_attempt(self):
        assert _validate_ip("10.0.0.5}:evil_key{") is None


class TestDdosVolumetric:
    def test_flags_a_real_connection_flood_to_one_destination(self, tracker):
        t0 = 1000.0
        for i in range(1200):
            tracker.record_connection("10.0.0.5", "10.0.0.99", t0 + i * 0.005)
        is_flood, stats = tracker.is_ddos_volumetric("10.0.0.5", "10.0.0.99", t0 + 6.0)
        assert is_flood is True
        assert stats["connection_count"] >= 1000

    def test_does_not_flag_ordinary_connection_volume(self, tracker):
        t0 = 1000.0
        for i in range(5):
            tracker.record_connection("10.0.0.5", "10.0.0.99", t0 + i * 2.0)
        is_flood, stats = tracker.is_ddos_volumetric("10.0.0.5", "10.0.0.99", t0 + 10.0)
        assert is_flood is False

    def test_does_not_flag_fan_out_across_many_destinations(self, tracker):
        # The real false-positive mode found during calibration: a
        # NAT/gateway-aggregated host makes many connections, but spread
        # across many distinct destinations -- never a flood at any ONE
        # destination. 1200 connections total, 400 per destination.
        t0 = 1000.0
        destinations = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
        for i in range(1200):
            tracker.record_connection("10.0.0.5", destinations[i % 3], t0 + i * 0.005)
        for dest in destinations:
            is_flood, stats = tracker.is_ddos_volumetric("10.0.0.5", dest, t0 + 6.0)
            assert is_flood is False, f"{dest} incorrectly flagged: {stats}"

    def test_old_connections_fall_out_of_the_window(self, tracker):
        # 1200 connections, but spread across a long time -- never more
        # than a handful within any real 10-second window.
        t0 = 1000.0
        for i in range(1200):
            tracker.record_connection("10.0.0.5", "10.0.0.99", t0 + i * 3.0)
        is_flood, stats = tracker.is_ddos_volumetric("10.0.0.5", "10.0.0.99", t0 + 1200 * 3.0)
        assert is_flood is False
        assert stats["connection_count"] < 1000

    def test_different_source_ips_are_isolated(self, tracker):
        t0 = 1000.0
        for i in range(1200):
            tracker.record_connection("10.0.0.5", "10.0.0.99", t0 + i * 0.005)
        is_flood_other, _ = tracker.is_ddos_volumetric("10.0.0.6", "10.0.0.99", t0 + 6.0)
        assert is_flood_other is False

    def test_invalid_ip_is_silently_ignored(self, tracker):
        tracker.record_connection("not-an-ip", "10.0.0.99", 1000.0)  # must not raise
        is_flood, stats = tracker.is_ddos_volumetric("not-an-ip", "10.0.0.99", 1000.0)
        assert is_flood is False
        assert stats["connection_count"] == 0

    def test_redis_error_is_logged_not_raised(self):
        broken_redis = MagicMock()
        broken_redis.pipeline.side_effect = RuntimeError("redis down")
        broken_redis.zcount.side_effect = RuntimeError("redis down")
        tracker = ConnBehaviorTracker(broken_redis)
        tracker.record_connection("10.0.0.5", "10.0.0.99", 1000.0)  # must not raise
        is_flood, stats = tracker.is_ddos_volumetric("10.0.0.5", "10.0.0.99", 1000.0)  # must not raise
        assert is_flood is False


class TestC2Beacon:
    def test_flags_regular_periodic_connections(self, tracker):
        t0 = 1000.0
        # Every ~60s, +/- 1s jitter -- a real beacon shape, matching the
        # real ~30-300s intervals found in CTU-13's own confirmed C2
        # channels during calibration.
        offsets = [0, 60, 119, 181, 240, 301, 359]
        for off in offsets:
            tracker.record_connection("10.0.0.5", "203.0.113.9", t0 + off)
        is_beacon, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.9", t0 + offsets[-1])
        assert is_beacon is True
        assert stats["observations"] == len(offsets)
        assert stats["coefficient_of_variation"] < 0.20

    def test_does_not_flag_irregular_human_driven_traffic(self, tracker):
        t0 = 1000.0
        # Wildly uneven gaps -- ordinary bursty browsing, not a beacon.
        offsets = [0, 8, 300, 305, 900, 1500, 1530]
        for off in offsets:
            tracker.record_connection("10.0.0.5", "203.0.113.9", t0 + off)
        is_beacon, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.9", t0 + offsets[-1])
        assert is_beacon is False

    def test_does_not_flag_a_rapid_burst_as_a_beacon(self, tracker):
        # Near-simultaneous connections have near-zero, near-uniform
        # intervals -- "perfectly regular" by variance alone, but not a
        # beacon; beacon_min_interval_seconds must guard against this.
        t0 = 1000.0
        for i in range(10):
            tracker.record_connection("10.0.0.5", "203.0.113.9", t0 + i * 0.05)
        is_beacon, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.9", t0 + 1.0)
        assert is_beacon is False

    def test_too_few_observations_does_not_flag(self, tracker):
        t0 = 1000.0
        for off in [0, 60, 120]:
            tracker.record_connection("10.0.0.5", "203.0.113.9", t0 + off)
        is_beacon, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.9", t0 + 120)
        assert is_beacon is False
        assert stats["observations"] == 3

    def test_different_destination_pairs_are_isolated(self, tracker):
        t0 = 1000.0
        offsets = [0, 60, 119, 181, 240, 301, 359]
        for off in offsets:
            tracker.record_connection("10.0.0.5", "203.0.113.9", t0 + off)
        is_beacon_other, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.99", t0 + offsets[-1])
        assert is_beacon_other is False
        assert stats["observations"] == 0

    def test_old_observations_fall_out_of_the_beacon_window(self, tracker):
        t0 = 1000.0
        offsets = [0, 60, 119, 181, 240, 301, 359]
        for off in offsets:
            tracker.record_connection("10.0.0.5", "203.0.113.9", t0 + off)
        # Far beyond the 1800s beacon window -- none of the above should
        # still be counted.
        is_beacon, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.9", t0 + offsets[-1] + 5000.0)
        assert is_beacon is False
        assert stats["observations"] == 0

    def test_invalid_ip_is_silently_ignored(self, tracker):
        tracker.record_connection("not-an-ip", "203.0.113.9", 1000.0)  # must not raise
        is_beacon, stats = tracker.is_c2_beacon("not-an-ip", "203.0.113.9", 1000.0)
        assert is_beacon is False
        assert stats["observations"] == 0

    def test_redis_error_is_logged_not_raised(self):
        broken_redis = MagicMock()
        broken_redis.pipeline.side_effect = RuntimeError("redis down")
        broken_redis.zrangebyscore.side_effect = RuntimeError("redis down")
        tracker = ConnBehaviorTracker(broken_redis)
        tracker.record_connection("10.0.0.5", "203.0.113.9", 1000.0)  # must not raise
        is_beacon, stats = tracker.is_c2_beacon("10.0.0.5", "203.0.113.9", 1000.0)  # must not raise
        assert is_beacon is False
