"""Parity test for scripts/_fast_conn_behavior.py's FastConnBehaviorTracker
-- the pure-Python stand-in built to make this project's real-data
evaluators fast (see that module's own docstring for the full story: a
widened BEACON_WINDOW_SECONDS made the real, fakeredis-backed
ConnBehaviorTracker take 30+ minutes to replay this project's ~800k-row
real CTU-13 dataset).

This is the thing that makes trusting the fast stand-in's numbers
legitimate rather than a hopeful guess: replays real CTU-13 connections
(the two smallest real scenarios, kept small so this runs in the normal
fast unit-test suite, not a real-data gate of its own) through BOTH the
real ConnBehaviorTracker (fakeredis-backed) and FastConnBehaviorTracker,
at the exact production-configured windows/thresholds, and asserts every
single is_ddos_volumetric()/is_c2_beacon()/is_bulk_exfil() decision is
identical.
"""
import csv
import os

import fakeredis

from inference.conn_behavior import ConnBehaviorTracker
from scripts._fast_conn_behavior import FastConnBehaviorTracker

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "benchmarks", "real_composite_dataset.csv")
PARITY_SCENARIOS = {"5", "7"}  # the two smallest real scenarios -- fast, still real


def _load_parity_rows():
    rows = []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["scenario"] in PARITY_SCENARIOS:
                rows.append((
                    row["scenario"], row["src_addr"], row["dst_addr"],
                    float(row["timestamp"]), float(row["orig_bytes"]),
                ))
    rows.sort(key=lambda r: (r[0], r[3]))
    return rows


def test_fast_tracker_matches_real_tracker_on_real_data():
    rows = _load_parity_rows()
    assert len(rows) > 5000, "parity sample should be a meaningful slice of real data"

    real = ConnBehaviorTracker(fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True))
    fast = FastConnBehaviorTracker()

    mismatches = []
    current_scenario = None
    for scenario, src, dst, ts, orig_bytes in rows:
        if scenario != current_scenario:
            # A fresh tracker per scenario, exactly like the real evaluators do.
            real = ConnBehaviorTracker(fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True))
            fast = FastConnBehaviorTracker()
            current_scenario = scenario

        real.record_connection(src, dst, ts, orig_bytes)
        fast.record_connection(src, dst, ts, orig_bytes)

        real_flood, _ = real.is_ddos_volumetric(src, dst, ts)
        fast_flood, _ = fast.is_ddos_volumetric(src, dst, ts)
        real_beacon, _ = real.is_c2_beacon(src, dst, ts)
        fast_beacon, _ = fast.is_c2_beacon(src, dst, ts)
        real_exfil, _ = real.is_bulk_exfil(src, dst, ts)
        fast_exfil, _ = fast.is_bulk_exfil(src, dst, ts)

        if (real_flood, real_beacon, real_exfil) != (fast_flood, fast_beacon, fast_exfil):
            mismatches.append((scenario, src, dst, ts))

    assert not mismatches, f"{len(mismatches)} decision mismatch(es), e.g. {mismatches[:5]}"
