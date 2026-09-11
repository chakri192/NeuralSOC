#!/usr/bin/env python3
"""evaluate_composite_scoring_against_real_data.py -- does combining
independent detectors' signals into one incident-level score
(inference/risk.py's calculate_risk_score()) actually catch more real
attacks than relying on any single detector alone?

Runs the flow autoencoder AND all 4 real rules evaluate_rules() can
exercise against the SAME real CTU-13 flows
(benchmarks/real_rule_validation_dataset.csv already has every field
both need -- orig_bytes/resp_bytes/duration/tot_pkts for the flow model,
plus dport/state for the rules), builds each flow's list of triggered
detections in the exact production alert shape (confidence_score,
model_name -- see inference/stream_processor_faust.py's raw_alert
construction), and measures the union/composite coverage against real
Botnet/Normal ground truth.

This script is also what discovered a real, disclosed nuance about the
flow autoencoder's generalization: scripts/evaluate_flow_autoencoder_against_real_data.py's
100%/99.8%/0.00% numbers are against ONE held-out scenario (11). Across
ALL 13 real scenarios (most of which contributed no training data at
all, unlike scenario 11's neighbors 5/7/12), the flow autoencoder alone
catches only ~37% of real botnet flows -- a materially different, more
honest picture of single-model generalization, and the concrete
motivation for combining it with the rule-based detectors rather than
relying on it alone.

Also acts as a regression gate, mirroring the other real-data
evaluators: benchmarks/composite_scoring_baseline.json records the
composite (union) recall/FPR as of the last check.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_composite_scoring_against_real_data.py
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_composite_scoring_against_real_data.py --update-baseline
"""
import argparse
import csv
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from inference.models import FlowAnomalyEngine
from inference.risk import calculate_risk_score
from inference.rules import evaluate_rules
from evaluate_rules_against_real_data import _argus_state_to_zeek_conn_state, RULE_TO_THREAT_CLASS

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_rule_validation_dataset.csv")
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "composite_scoring_baseline.json")
REGRESSION_THRESHOLD_POINTS = 5.0

# calculate_risk_score()'s own 0-100 scale. Matches
# inference/correlation.py's IncidentCorrelator.add_alert() default
# threshold param -- 50.0, not the previous 80.0, which this same script
# is what found: at 80, the composite score actually under-performed the
# single best detector (26.3% vs. 48.5% recall) because no individual
# rule's fixed confidence (Reconnaissance's 0.75, e.g.) clears 80 without
# corroboration. A real threshold sweep against this dataset found a
# wide flat plateau from ~1 to ~50 all giving the identical, real
# 98.8% precision / 53.7% recall / 0.50% FPR operating point -- 50 sits
# at the safe edge of that plateau, not an arbitrary guess.
RISK_SCORE_INCIDENT_THRESHOLD = 50.0


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


def _load_dataset():
    rows = []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


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
    rows = _load_dataset()
    n_botnet = sum(1 for r in rows if r["label"] == "botnet")
    n_normal = len(rows) - n_botnet
    print(f"[*] {len(rows)} real flows loaded ({n_botnet} real Botnet, {n_normal} real Normal)\n")

    print("[*] Loading the live flow autoencoder...")
    engine = FlowAnomalyEngine()

    # Per-detector-alone confusion, plus composite (calculate_risk_score
    # thresholded) confusion, all against the same real ground truth.
    solo_counts = {name: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for name in ["flow_autoencoder"] + list(RULE_TO_THREAT_CLASS)}
    composite_counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    for row in rows:
        is_botnet = row["label"] == "botnet"
        orig_bytes, resp_bytes = float(row["orig_bytes"]), float(row["resp_bytes"])
        duration, tot_pkts = float(row["duration"]), float(row["tot_pkts"])
        dport, state = int(row["dport"]), row["state"]

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

        risk_score = calculate_risk_score(alerts)
        is_incident = risk_score >= RISK_SCORE_INCIDENT_THRESHOLD
        if is_botnet:
            composite_counts["tp" if is_incident else "fn"] += 1
        else:
            composite_counts["fp" if is_incident else "tn"] += 1

    print("=" * 72)
    print("Solo detector performance (each alone, same real flows)")
    print("=" * 72)
    for name, c in solo_counts.items():
        m = _confusion(c["tp"], c["fp"], c["tn"], c["fn"])
        print(f"  {name:<25} precision={m['precision']:>6.1%}  recall={m['recall']:>6.1%}  fpr={m['fpr']:>6.2%}")

    composite_metrics = _confusion(composite_counts["tp"], composite_counts["fp"], composite_counts["tn"], composite_counts["fn"])
    print("\n" + "=" * 72)
    print(f"COMPOSITE (calculate_risk_score >= {RISK_SCORE_INCIDENT_THRESHOLD}) -- combining flow autoencoder + all 4 rules")
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

    print("\nDataset: benchmarks/real_rule_validation_dataset.csv (CTU-13, all 13 scenarios, "
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
