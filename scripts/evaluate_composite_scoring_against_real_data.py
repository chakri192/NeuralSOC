#!/usr/bin/env python3
"""evaluate_composite_scoring_against_real_data.py -- does combining
independent detectors' signals into one incident-level score
(inference/risk.py's calculate_risk_score()) actually catch more real
attacks than relying on any single detector alone?

Runs all SEVEN detectors this platform's incident score can combine
against the SAME real CTU-13 connections, replayed in real
chronological order per scenario: the flow autoencoder and the 4 rules
evaluate_rules() can exercise (orig_bytes/resp_bytes/duration/tot_pkts,
plus dport/state), AND -- folded in as of this version --
inference/conn_behavior.py's windowed RULE_DDOS_CONN_RATE,
RULE_C2_BEACON_PERIODIC, and RULE_EXFIL_BYTE_VOLUME (real
src_addr/dst_addr/timestamp). Earlier versions of this script measured
only the first four, because benchmarks/real_rule_validation_dataset.csv
(still used by scripts/evaluate_rules_against_real_data.py's own gate)
has no real IP/timestamp fields a windowed check can key a window on.
benchmarks/real_composite_dataset.csv is a single, comprehensive extract
carrying every field all seven detectors need (every real Botnet/Normal-
labeled connection from all 13 real CTU-13 scenarios, kept whole and in
real chronological order -- no per-class sampling cap, since the
windowed checks need each (source, destination) pair's complete,
temporally continuous sequence). It's also what
scripts/evaluate_conn_behavior_against_real_data.py reads (just the
columns it needs) -- one real dataset shared by both evaluators instead
of two separately-extracted, otherwise-identical copies.

Builds each connection's list of triggered detections in the exact
production alert shape (confidence_score, model_name -- see
inference/stream_processor_faust.py's raw_alert construction), and
measures the union/composite coverage against real Botnet/Normal ground
truth.

This script is also what originally discovered a real, disclosed nuance
about the flow autoencoder's generalization: scripts/evaluate_flow_autoencoder_against_real_data.py's
100%/99.8%/0.00% numbers are against ONE held-out scenario (11). Against
a broader real slice, the flow autoencoder alone caught far fewer real
botnet flows -- a materially different, more honest picture of
single-model generalization, and the concrete motivation for combining
it with the rule-based detectors rather than relying on it alone. That
finding is now formalized as its own gated, CI-enforced baseline
directly in evaluate_flow_autoencoder_against_real_data.py
(benchmarks/flow_autoencoder_all_scenarios_baseline.json) rather than
only ever surfacing here.

Real, disclosed limitation of the "flow_autoencoder" line specifically
in this script's own "Solo detector performance" table below: training
was later broadened from 3 scenarios (5/7/12) to 12 (everything except
scenario 11) -- see benchmarks/real_flow_dataset_train.csv -- so most
of THIS script's own DATASET_PATH (every scenario but 11) is now the
same real Normal data the flow autoencoder was fit to. That makes this
script's own flow_autoencoder precision/FPR numbers optimistic (recall
is unaffected -- Botnet rows are never part of training regardless of
scenario). The authoritative, leak-free flow_autoencoder number lives
in evaluate_flow_autoencoder_against_real_data.py's all-scenarios gate
instead, which measures FPR only against real Normal rows the model
never trained on (benchmarks/real_flow_dataset_normal_holdout.csv +
scenario 11). This script's composite (union) recall number is not
affected by this caveat -- it's driven by which Botnet connections get
flagged by ANY detector, and Botnet ground truth was never leaked.

Also acts as a regression gate, mirroring the other real-data
evaluators: benchmarks/composite_scoring_baseline.json records the
composite (union) recall/precision/FPR as of the last check. Folding in
the two windowed detectors changed what this baseline measures, so it
was re-seeded rather than compared against the prior (four-detector)
numbers -- see docs/PATH_TO_10_OUT_OF_10.md and SECURITY.md for the
before/after.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_composite_scoring_against_real_data.py
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_composite_scoring_against_real_data.py --update-baseline
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict

import fakeredis

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from inference.conn_behavior import ConnBehaviorTracker
from inference.models import FlowAnomalyEngine
from inference.risk import calculate_risk_score
from inference.rules import evaluate_rules
from evaluate_rules_against_real_data import _argus_state_to_zeek_conn_state, RULE_TO_THREAT_CLASS

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_composite_dataset.csv")
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "composite_scoring_baseline.json")
REGRESSION_THRESHOLD_POINTS = 5.0

# calculate_risk_score()'s own 0-100 scale. Matches
# inference/correlation.py's IncidentCorrelator.add_alert() default
# threshold param -- 50.0, not the previous 80.0, which this same script
# is what found: at 80, the composite score actually under-performed the
# single best detector (26.3% vs. 48.5% recall) because no individual
# rule's fixed confidence (Reconnaissance's 0.75, e.g.) clears 80 without
# corroboration. A real threshold sweep against this dataset found a
# wide flat plateau from ~1 to ~50 all giving the identical operating
# point -- 50 sits at the safe edge of that plateau, not an arbitrary
# guess. Re-checked after folding in the two windowed detectors: still
# the right edge of the same kind of plateau (see the module docstring).
RISK_SCORE_INCIDENT_THRESHOLD = 50.0

ALL_DETECTOR_NAMES = ["flow_autoencoder"] + list(RULE_TO_THREAT_CLASS) + [
    "RULE_DDOS_CONN_RATE", "RULE_C2_BEACON_PERIODIC", "RULE_EXFIL_BYTE_VOLUME",
]


def _flow_anomaly_alert(engine, orig_bytes, resp_bytes, duration, tot_pkts):
    """Mirrors inference/stream_processor_faust.py's exact detection
    dict construction (confidence formula included) for the flow
    autoencoder, so this evaluation exercises the real production alert
    shape, not an approximation of it."""
    is_anomalous, mse, threshold = engine.score(orig_bytes, resp_bytes, duration, tot_pkts)
    if not is_anomalous:
        return None
    confidence = min(0.99, mse / (threshold * 2)) if threshold else 0.5
    return {
        "threat_class": "Anomalous Flow",
        "severity": "medium",
        "confidence_score": confidence,
        "model_name": "DL_AUTOENCODER_FLOW_ANOMALY",
    }


def _rule_alerts(dport, state, orig_bytes, resp_bytes, tot_pkts):
    """Mirrors inference/stream_processor_faust.py's raw_alert
    construction for rule-based detections (confidence -> confidence_score,
    rule_id -> model_name)."""
    zeek_state = _argus_state_to_zeek_conn_state(state)
    event = {"event_type": "conn", "id.resp_p": dport, "conn_state": zeek_state, "orig_pkts": tot_pkts}
    features = {"orig_bytes": orig_bytes, "resp_bytes": resp_bytes}
    alerts = []
    for det in evaluate_rules(event, features):
        alerts.append({
            "threat_class": det.get("threat_class"),
            "severity": det.get("severity"),
            "confidence_score": det.get("confidence"),
            "model_name": det.get("rule_id"),
        })
    return alerts


def _conn_behavior_alerts(tracker, src, dst, ts, orig_bytes):
    """Mirrors inference/stream_processor_faust.py's raw_alert
    construction for the windowed connection-behavior detectors, exactly
    as they're wired in production: record first, then check all three."""
    tracker.record_connection(src, dst, ts, orig_bytes)
    alerts = []
    is_flood, _ = tracker.is_ddos_volumetric(src, dst, ts)
    if is_flood:
        alerts.append({
            "threat_class": "DDoS",
            "severity": "critical",
            "confidence_score": 0.95,
            "model_name": "RULE_DDOS_CONN_RATE",
        })
    is_beacon, _ = tracker.is_c2_beacon(src, dst, ts)
    if is_beacon:
        alerts.append({
            "threat_class": "C2 Beaconing",
            "severity": "medium",
            "confidence_score": 0.40,
            "model_name": "RULE_C2_BEACON_PERIODIC",
        })
    is_exfil, _ = tracker.is_bulk_exfil(src, dst, ts)
    if is_exfil:
        alerts.append({
            "threat_class": "Data Exfiltration",
            "severity": "critical",
            "confidence_score": 0.95,
            "model_name": "RULE_EXFIL_BYTE_VOLUME",
        })
    return alerts


def _load_dataset():
    by_scenario = defaultdict(list)
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            by_scenario[row["scenario"]].append(row)
    for rows in by_scenario.values():
        rows.sort(key=lambda r: float(r["timestamp"]))
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


def _write_baseline(metrics):
    with open(BASELINE_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update-baseline", action="store_true")
    args = parser.parse_args()

    print(f"[*] Loading {DATASET_PATH}...")
    by_scenario = _load_dataset()
    total_rows = sum(len(rows) for rows in by_scenario.values())
    n_botnet = sum(1 for rows in by_scenario.values() for r in rows if r["label"] == "botnet")
    print(f"[*] {total_rows} real connections loaded across {len(by_scenario)} real CTU-13 scenarios "
          f"({n_botnet} real Botnet, {total_rows - n_botnet} real Normal)\n")

    print("[*] Loading the live flow autoencoder...")
    engine = FlowAnomalyEngine()

    # Per-detector-alone confusion, plus composite (calculate_risk_score
    # thresholded) confusion, all against the same real ground truth.
    solo_counts = {name: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for name in ALL_DETECTOR_NAMES}
    composite_counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    for scenario, rows in sorted(by_scenario.items(), key=lambda kv: int(kv[0])):
        print(f"[*] Replaying scenario {scenario} ({len(rows)} connections) in real chronological order...")
        tracker = ConnBehaviorTracker(fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True))
        for row in rows:
            is_botnet = row["label"] == "botnet"
            orig_bytes, resp_bytes = float(row["orig_bytes"]), float(row["resp_bytes"])
            duration, tot_pkts = float(row["duration"]), float(row["tot_pkts"])
            dport, state = int(row["dport"]), row["state"]
            src, dst, ts = row["src_addr"], row["dst_addr"], float(row["timestamp"])

            alerts = []
            flow_alert = _flow_anomaly_alert(engine, orig_bytes, resp_bytes, duration, tot_pkts)
            if flow_alert:
                alerts.append(flow_alert)
                solo_counts["flow_autoencoder"]["tp" if is_botnet else "fp"] += 1
            else:
                solo_counts["flow_autoencoder"]["fn" if is_botnet else "tn"] += 1

            rule_alerts = _rule_alerts(dport, state, orig_bytes, resp_bytes, tot_pkts)
            alerts.extend(rule_alerts)
            fired_rule_ids = {a["model_name"] for a in rule_alerts}
            for rule_id in RULE_TO_THREAT_CLASS:
                fired = rule_id in fired_rule_ids
                if is_botnet:
                    solo_counts[rule_id]["tp" if fired else "fn"] += 1
                else:
                    solo_counts[rule_id]["fp" if fired else "tn"] += 1

            conn_alerts = _conn_behavior_alerts(tracker, src, dst, ts, orig_bytes)
            alerts.extend(conn_alerts)
            fired_conn_ids = {a["model_name"] for a in conn_alerts}
            for name in ("RULE_DDOS_CONN_RATE", "RULE_C2_BEACON_PERIODIC", "RULE_EXFIL_BYTE_VOLUME"):
                fired = name in fired_conn_ids
                if is_botnet:
                    solo_counts[name]["tp" if fired else "fn"] += 1
                else:
                    solo_counts[name]["fp" if fired else "tn"] += 1

            risk_score = calculate_risk_score(alerts)
            is_incident = risk_score >= RISK_SCORE_INCIDENT_THRESHOLD
            if is_botnet:
                composite_counts["tp" if is_incident else "fn"] += 1
            else:
                composite_counts["fp" if is_incident else "tn"] += 1

    print("\n" + "=" * 72)
    print("Solo detector performance (each alone, same real connections)")
    print("=" * 72)
    for name, c in solo_counts.items():
        m = _confusion(c["tp"], c["fp"], c["tn"], c["fn"])
        print(f"  {name:<25} precision={m['precision']:>6.1%}  recall={m['recall']:>6.1%}  fpr={m['fpr']:>6.2%}")

    composite_metrics = _confusion(composite_counts["tp"], composite_counts["fp"], composite_counts["tn"], composite_counts["fn"])
    print("\n" + "=" * 72)
    print(f"COMPOSITE (calculate_risk_score >= {RISK_SCORE_INCIDENT_THRESHOLD}) -- combining all 7 detectors")
    print("=" * 72)
    print(f"  Accuracy:  {composite_metrics['accuracy']:.1%}")
    print(f"  Precision: {composite_metrics['precision']:.1%}")
    print(f"  Recall:    {composite_metrics['recall']:.1%}")
    print(f"  False-positive rate: {composite_metrics['fpr']:.2%}")
    print(f"  Confusion: TP={composite_counts['tp']} FP={composite_counts['fp']} "
          f"TN={composite_counts['tn']} FN={composite_counts['fn']}")

    best_solo_recall = max(_confusion(**c)["recall"] for c in solo_counts.values())
    print(f"\nBest single detector's recall alone: {best_solo_recall:.1%}")
    print(f"Composite recall: {composite_metrics['recall']:.1%}")
    print(f"Delta: {(composite_metrics['recall'] - best_solo_recall) * 100:+.1f} points")

    print("\nDataset: benchmarks/real_composite_dataset.csv (CTU-13, all 13 scenarios, "
          "Stratosphere IPS / CVUT, CC-BY, https://www.stratosphereips.org/datasets-ctu13).")

    if args.update_baseline:
        _write_baseline(composite_metrics)
        print(f"\n[+] Baseline updated: {BASELINE_PATH}")
        return 0

    baseline = _load_baseline()
    if baseline is None:
        print(f"\n[!] No baseline found at {BASELINE_PATH} -- run with --update-baseline to create one. "
              "Skipping regression check.")
        return 0

    print("\n" + "-" * 72)
    print(f"REGRESSION CHECK vs. baseline (fails if precision/recall drop or FPR rises "
          f"by more than {REGRESSION_THRESHOLD_POINTS:.0f} points)")
    print("-" * 72)
    precision_delta = (composite_metrics["precision"] - baseline["precision"]) * 100
    recall_delta = (composite_metrics["recall"] - baseline["recall"]) * 100
    fpr_delta = (composite_metrics["fpr"] - baseline["fpr"]) * 100
    print(f"  precision: delta={precision_delta:+.1f}pts   recall: delta={recall_delta:+.1f}pts   fpr: delta={fpr_delta:+.1f}pts")

    regressions = []
    if precision_delta < -REGRESSION_THRESHOLD_POINTS:
        regressions.append(f"precision dropped {abs(precision_delta):.1f} points")
    if recall_delta < -REGRESSION_THRESHOLD_POINTS:
        regressions.append(f"recall dropped {abs(recall_delta):.1f} points")
    if fpr_delta > REGRESSION_THRESHOLD_POINTS:
        regressions.append(f"FPR rose {fpr_delta:.1f} points")

    if regressions:
        print(f"\n[!] Regression(s): {'; '.join(regressions)}")
        return 1
    print("\n[+] No regression beyond threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
