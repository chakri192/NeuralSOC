#!/usr/bin/env python3
"""evaluate_flow_autoencoder_against_real_data.py -- the flow-autoencoder
equivalent of scripts/evaluate_against_real_dga_dataset.py: has the flow
autoencoder ever been tested against real attack traffic, or only its
own synthetic generator?

benchmarks/real_flow_dataset_test.csv is a held-out extract from the
CTU-13 dataset (Stratosphere IPS / CVUT, CC-BY,
https://www.stratosphereips.org/datasets-ctu13) -- real botnet-infected
host traffic and real confirmed-clean host traffic, captured on a real
university network, labeled by CTU-13's own researchers against the
actual malware samples. Scenario 11 specifically, held out from
benchmarks/real_flow_dataset_train.csv (scenarios 5/7/12, used to
augment FlowAnomalyEngine's synthetic training data) -- different
capture files entirely, the same train/test separation discipline
benchmarks/real_dga_domains.csv follows.

CTU-13's own 3-way labeling: "Botnet" flows are confirmed malicious
traffic from the infected host, "Normal" flows are confirmed-clean
traffic from a specific known-clean host, "Background" is unlabeled
ambient noise (neither confirmed benign nor malicious) -- only
Botnet/Normal rows are included in this CSV, so recall/FPR here reflect
real ground truth, not unlabeled traffic of unknown composition.

Real, honest limitation: CTU-13's .binetflow (Argus) format reports
TotPkts (both directions combined), not per-direction packet counts.
FlowAnomalyEngine was trained on orig_pkts specifically (packets FROM
the flow's originator only, per Zeek conn-log convention -- see
ingest/pcap_ingester.py). TotPkts is the closest available real-world
proxy and is what's stored in this CSV's tot_pkts column; this is
disclosed, not hidden, and is the single biggest source of feature
mismatch between what this script measures and production's exact
feature computation.

Also acts as a regression gate, mirroring
scripts/evaluate_against_real_dga_dataset.py's own baseline comparison:
benchmarks/flow_autoencoder_baseline.json records precision/recall/FPR
as of the last deliberate retrain, and every run compares against it,
exiting non-zero if recall/precision drop or FPR rises by more than
REGRESSION_THRESHOLD_POINTS. Pass --update-baseline after a deliberate
retrain to accept new numbers as the baseline going forward.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_flow_autoencoder_against_real_data.py
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_flow_autoencoder_against_real_data.py --limit 2000
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_flow_autoencoder_against_real_data.py --update-baseline
"""
import argparse
import csv
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.models import FlowAnomalyEngine

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_flow_dataset_test.csv")
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "flow_autoencoder_baseline.json")
REGRESSION_THRESHOLD_POINTS = 5.0


def _load_dataset(limit=None):
    rows = []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append((
                row["label"] == "botnet",
                float(row["orig_bytes"]),
                float(row["resp_bytes"]),
                float(row["duration"]),
                float(row["tot_pkts"]),
            ))
    if limit:
        rows = rows[:limit]
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
    parser.add_argument("--limit", type=int, default=None, help="Only evaluate the first N rows (default: all)")
    parser.add_argument("--update-baseline", action="store_true",
                         help="Overwrite benchmarks/flow_autoencoder_baseline.json with this run's numbers "
                              "(only after a deliberate retrain, not to silence a real regression)")
    args = parser.parse_args()

    print(f"[*] Loading {DATASET_PATH}...")
    rows = _load_dataset(args.limit)
    n_botnet = sum(1 for is_botnet, *_ in rows if is_botnet)
    n_normal = len(rows) - n_botnet
    print(f"[*] {len(rows)} real flows loaded ({n_botnet} real Botnet, {n_normal} real Normal)\n")

    print("[*] Loading the live flow autoencoder (models/autoencoder_flow.pt)...")
    engine = FlowAnomalyEngine()

    tp = fp = tn = fn = 0
    for is_botnet, orig_bytes, resp_bytes, duration, tot_pkts in rows:
        is_anomalous, _, _ = engine.score(orig_bytes, resp_bytes, duration, tot_pkts)
        if is_botnet:
            tp += int(is_anomalous)
            fn += int(not is_anomalous)
        else:
            fp += int(is_anomalous)
            tn += int(not is_anomalous)

    metrics = _confusion(tp, fp, tn, fn)
    print("\n" + "=" * 72)
    print("RESULTS -- flow autoencoder against real CTU-13 botnet/normal flows")
    print("=" * 72)
    print(f"  Accuracy:  {metrics['accuracy']:.1%}")
    print(f"  Precision: {metrics['precision']:.1%}   (of what it flagged, how much was really Botnet)")
    print(f"  Recall:    {metrics['recall']:.1%}   (of real Botnet flows, how many it caught)")
    print(f"  False-positive rate: {metrics['fpr']:.2%}   (real Normal flows wrongly flagged)")
    print(f"  Confusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    print("\nDataset: benchmarks/real_flow_dataset_test.csv (CTU-13 scenario 11, Stratosphere IPS / "
          "CVUT, CC-BY, https://www.stratosphereips.org/datasets-ctu13) -- real botnet-infected host "
          "traffic and real confirmed-clean host traffic, not this project's own simulator.")

    if args.update_baseline:
        _write_baseline(metrics)
        print(f"\n[+] Baseline updated: {BASELINE_PATH}")
        print(f"    precision={metrics['precision']:.1%} recall={metrics['recall']:.1%} fpr={metrics['fpr']:.2%}")
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
    precision_delta = (metrics["precision"] - baseline["precision"]) * 100
    recall_delta = (metrics["recall"] - baseline["recall"]) * 100
    fpr_delta = (metrics["fpr"] - baseline["fpr"]) * 100
    print(f"  precision: baseline={baseline['precision']:.1%}  current={metrics['precision']:.1%}  delta={precision_delta:+.1f}pts")
    print(f"  recall:    baseline={baseline['recall']:.1%}  current={metrics['recall']:.1%}  delta={recall_delta:+.1f}pts")
    print(f"  fpr:       baseline={baseline['fpr']:.2%}  current={metrics['fpr']:.2%}  delta={fpr_delta:+.1f}pts")

    regressions = []
    if precision_delta < -REGRESSION_THRESHOLD_POINTS:
        regressions.append(f"precision dropped {abs(precision_delta):.1f} points")
    if recall_delta < -REGRESSION_THRESHOLD_POINTS:
        regressions.append(f"recall dropped {abs(recall_delta):.1f} points")
    if fpr_delta > REGRESSION_THRESHOLD_POINTS:
        regressions.append(f"FPR rose {fpr_delta:.1f} points")

    if regressions:
        print(f"\n[!] Regression(s) beyond {REGRESSION_THRESHOLD_POINTS:.0f} points:")
        for r in regressions:
            print(f"    {r}")
        print("[!] If this is expected (a deliberate trade-off from a real retrain), "
              "re-run with --update-baseline to accept it.")
        return 1

    print("\n[+] No regression beyond threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
