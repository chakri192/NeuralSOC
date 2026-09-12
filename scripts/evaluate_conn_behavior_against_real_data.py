#!/usr/bin/env python3
"""evaluate_conn_behavior_against_real_data.py -- does
inference/conn_behavior.py's ConnBehaviorTracker (windowed DDoS-rate,
C2-periodicity, and bulk-exfil byte-volume detection) actually catch
real attacks, and at what real cost?

benchmarks/real_composite_dataset.csv (shared with
scripts/evaluate_composite_scoring_against_real_data.py, which needs the
same real per-connection rows plus flow-level fields this script doesn't
use) carries real SrcAddr/DstAddr/StartTime/Label rows extracted from
all 13 raw CTU-13 .binetflow files (Stratosphere IPS / CVUT, CC-BY) --
every real Botnet- and Normal-labeled row, kept whole and in real
chronological order per scenario (unlike
benchmarks/real_rule_validation_dataset.csv's per-class sampling cap: a
windowed rate/periodicity check needs each (source, destination) pair's
COMPLETE, temporally continuous real sequence, so this dataset is larger
than this project's smaller benchmarks -- randomly dropping rows would
silently destroy the exact bursts and regular intervals being measured).
CTU-13's own "Background" bucket (unlabeled ambient noise, not confirmed
benign) is excluded, matching every other real-data evaluator here.

Runs _fast_conn_behavior.py's FastConnBehaviorTracker -- a pure-Python
stand-in for the real, Redis-backed ConnBehaviorTracker production code
hits (inference/stream_processor_faust.py's wiring), verified in
tests/unit/test_fast_conn_behavior.py to make identical decisions on real
data. Built because the real, fakeredis-backed tracker's per-call cost
scales with how much history a busy pair has accumulated, and became
impractically slow (30+ minutes for this ~800k-row real dataset) once
BEACON_WINDOW_SECONDS was widened from 30 minutes to 6 hours to catch real
C2 beacons that fire on that timescale -- see _fast_conn_behavior.py's own
docstring for the full story. Real chronological order per scenario --
record_connection() then immediately is_ddos_volumetric()/is_c2_beacon()/
is_bulk_exfil(), the same record-then-check sequence the live stream
processor uses. A real "connection event" from CTU-13 gets counted as a
true positive the moment any check fires while replaying a real
Botnet-labeled row, and a false positive the moment any fires on a real
Normal-labeled row.

This is a genuinely two-tier signal, real-data calibrated (see
inference/conn_behavior.py's own module docstring for the full story):
DDoS-rate and bulk-exfil are both strong (100% precision at their
thresholds); C2-periodicity is real but weak alone, which is why it's
fed into inference/risk.py's log-odds pooling at low confidence rather
than trusted standalone.

Also acts as a regression gate, mirroring every other real-data
evaluator in this project: benchmarks/conn_behavior_baseline.json
records precision/recall/FPR for each detector as of the last check, and
every run compares against it. Pass --update-baseline after a
deliberate, evidence-based change.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_conn_behavior_against_real_data.py
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_conn_behavior_against_real_data.py --update-baseline
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _fast_conn_behavior import FastConnBehaviorTracker  # noqa: E402

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_composite_dataset.csv")
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "conn_behavior_baseline.json")
REGRESSION_THRESHOLD_POINTS = 5.0


def _load_dataset():
    by_scenario = defaultdict(list)
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            by_scenario[row["scenario"]].append((
                row["label"] == "botnet",
                row["src_addr"],
                row["dst_addr"],
                float(row["timestamp"]),
                float(row["orig_bytes"]),
            ))
    for scenario_rows in by_scenario.values():
        scenario_rows.sort(key=lambda r: r[3])
    return by_scenario


def _confusion(tp, fp, tn, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "fpr": fpr}


def _load_baseline():
    if not os.path.exists(BASELINE_PATH):
        return None
    with open(BASELINE_PATH, encoding="utf-8") as f:
        return json.load(f)


def _write_baseline(metrics_by_detector):
    with open(BASELINE_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_by_detector, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update-baseline", action="store_true",
                         help="Overwrite benchmarks/conn_behavior_baseline.json with this run's numbers "
                              "(only after a deliberate, evidence-based threshold change)")
    args = parser.parse_args()

    print(f"[*] Loading {DATASET_PATH}...", flush=True)
    by_scenario = _load_dataset()
    total_rows = sum(len(rows) for rows in by_scenario.values())
    total_botnet = sum(1 for rows in by_scenario.values() for is_botnet, *_ in rows if is_botnet)
    print(f"[*] {total_rows} real connections loaded across {len(by_scenario)} real CTU-13 scenarios "
          f"({total_botnet} real Botnet, {total_rows - total_botnet} real confirmed-clean Normal)\n", flush=True)

    counts = {
        "RULE_DDOS_CONN_RATE": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "RULE_C2_BEACON_PERIODIC": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "RULE_EXFIL_BYTE_VOLUME": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
    }

    for scenario, rows in sorted(by_scenario.items(), key=lambda kv: int(kv[0])):
        print(f"[*] Replaying scenario {scenario} ({len(rows)} connections) in real chronological order...", flush=True)
        tracker = FastConnBehaviorTracker()
        for is_botnet, src, dst, ts, orig_bytes in rows:
            tracker.record_connection(src, dst, ts, orig_bytes)
            is_flood, _ = tracker.is_ddos_volumetric(src, dst, ts)
            is_beacon, _ = tracker.is_c2_beacon(src, dst, ts)
            is_exfil, _ = tracker.is_bulk_exfil(src, dst, ts)
            if is_botnet:
                counts["RULE_DDOS_CONN_RATE"]["tp" if is_flood else "fn"] += 1
                counts["RULE_C2_BEACON_PERIODIC"]["tp" if is_beacon else "fn"] += 1
                counts["RULE_EXFIL_BYTE_VOLUME"]["tp" if is_exfil else "fn"] += 1
            else:
                counts["RULE_DDOS_CONN_RATE"]["fp" if is_flood else "tn"] += 1
                counts["RULE_C2_BEACON_PERIODIC"]["fp" if is_beacon else "tn"] += 1
                counts["RULE_EXFIL_BYTE_VOLUME"]["fp" if is_exfil else "tn"] += 1

    print("\n" + "=" * 72)
    print("RESULTS -- windowed connection-behavior detectors against real CTU-13 traffic")
    print("=" * 72)
    metrics_by_detector = {}
    for rule_id, c in counts.items():
        m = _confusion(c["tp"], c["fp"], c["tn"], c["fn"])
        metrics_by_detector[rule_id] = m
        print(f"\n{rule_id}")
        print(f"  Accuracy:  {m['accuracy']:.1%}")
        print(f"  Precision: {m['precision']:.1%}   (of what it flagged, how much was really Botnet)")
        print(f"  Recall:    {m['recall']:.1%}   (of real Botnet connections, how many it caught)")
        print(f"  False-positive rate: {m['fpr']:.2%}   (real confirmed-clean connections wrongly flagged)")
        print(f"  Confusion: TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}")

    print("\nDataset: benchmarks/real_composite_dataset.csv (CTU-13, all 13 scenarios, "
          "Stratosphere IPS / CVUT, CC-BY, https://www.stratosphereips.org/datasets-ctu13) -- "
          "real infected-host and real confirmed-clean-host connections, not this project's own simulator.")

    if args.update_baseline:
        _write_baseline(metrics_by_detector)
        print(f"\n[+] Baseline updated: {BASELINE_PATH}")
        return 0

    baseline = _load_baseline()
    if baseline is None:
        print(f"\n[!] No baseline found at {BASELINE_PATH} -- run with --update-baseline to create one. "
              "Skipping regression check.")
        return 0

    print("\n" + "-" * 72)
    print(f"REGRESSION CHECK vs. baseline (fails if precision/recall drops or FPR rises "
          f"by more than {REGRESSION_THRESHOLD_POINTS:.0f} points)")
    print("-" * 72)
    regressions = []
    for rule_id, m in metrics_by_detector.items():
        b = baseline.get(rule_id)
        if b is None:
            print(f"  {rule_id:<25} (new detector, no baseline yet)")
            continue
        precision_delta = (m["precision"] - b["precision"]) * 100
        recall_delta = (m["recall"] - b["recall"]) * 100
        fpr_delta = (m["fpr"] - b["fpr"]) * 100
        print(f"  {rule_id:<25} precision={precision_delta:+6.1f}pts  recall={recall_delta:+6.1f}pts  fpr={fpr_delta:+6.1f}pts")
        if precision_delta < -REGRESSION_THRESHOLD_POINTS:
            regressions.append(f"{rule_id}: precision dropped {abs(precision_delta):.1f} points")
        if recall_delta < -REGRESSION_THRESHOLD_POINTS:
            regressions.append(f"{rule_id}: recall dropped {abs(recall_delta):.1f} points")
        if fpr_delta > REGRESSION_THRESHOLD_POINTS:
            regressions.append(f"{rule_id}: FPR rose {fpr_delta:.1f} points")

    if regressions:
        print(f"\n[!] {len(regressions)} regression(s) beyond {REGRESSION_THRESHOLD_POINTS:.0f} points:")
        for r in regressions:
            print(f"    {r}")
        print("[!] If this is expected (a deliberate, evidence-based threshold change), "
              "re-run with --update-baseline to accept it.")
        return 1

    print("\n[+] No regressions beyond threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
