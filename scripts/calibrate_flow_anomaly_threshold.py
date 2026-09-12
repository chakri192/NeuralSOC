#!/usr/bin/env python3
"""calibrate_flow_anomaly_threshold.py -- the flow-autoencoder equivalent
of scripts/calibrate_dga_threshold.py: shows what FLOW_ANOMALY_THRESHOLD
(inference/models.py) actually costs and buys, at every candidate value,
against the real held-out benchmark
scripts/evaluate_flow_autoencoder_against_real_data.py uses.

Worth a coarse-then-fine sweep, not just one pass: this model's real
Normal/Botnet reconstruction-error distributions turned out to be tightly
bimodal (most flows within each class cluster at nearly the same error
value) with a narrow separating gap -- a coarse sweep at round-number
steps can straddle both clusters at once and make the model look far
worse than it is. See SECURITY.md's "Flow autoencoder validation"
section for the concrete numbers this produced.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/calibrate_flow_anomaly_threshold.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.models import FlowAnomalyEngine

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from evaluate_flow_autoencoder_against_real_data import (  # noqa: E402
    ALL_SCENARIOS_DATASET_PATH,
    NEVER_TRAINED_NORMAL_HOLDOUT_PATH,
    _load_all_scenarios_rows_without_train_leakage,
)

CANDIDATE_THRESHOLDS = [0.001, 0.002, 0.003, 0.005, 0.007, 0.01, 0.011, 0.012, 0.013, 0.014, 0.015, 0.017, 0.02, 0.05, 0.1]


def _confusion_at(botnet_mse, normal_mse, thresh):
    tp = sum(1 for m in botnet_mse if m > thresh)
    fn = len(botnet_mse) - tp
    fp = sum(1 for m in normal_mse if m > thresh)
    tn = len(normal_mse) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "fpr": fpr, "accuracy": accuracy}


def main():
    print("[*] Loading the live flow autoencoder (models/autoencoder_flow.pt) -- scoring raw MSE, "
          "not gated by the currently-configured threshold...")
    engine = FlowAnomalyEngine()
    current = engine.threshold

    rows = _load_all_scenarios_rows_without_train_leakage(ALL_SCENARIOS_DATASET_PATH, NEVER_TRAINED_NORMAL_HOLDOUT_PATH)
    botnet_mse, normal_mse = [], []
    for is_botnet, orig_bytes, resp_bytes, duration, tot_pkts in rows:
        _, mse, _ = engine.score(orig_bytes, resp_bytes, duration, tot_pkts)
        (botnet_mse if is_botnet else normal_mse).append(mse)

    print(f"\nCurrently configured threshold: {current}")
    print(f"(set FLOW_ANOMALY_THRESHOLD and re-run this script to see a different value's real cost/benefit)\n")

    print(f"{'threshold':>10} {'TP':>6} {'FP':>6} {'TN':>6} {'FN':>6} {'precision':>10} {'recall':>8} {'fpr':>8} {'accuracy':>9}")
    thresholds = sorted(set(CANDIDATE_THRESHOLDS) | {current})
    for thresh in thresholds:
        m = _confusion_at(botnet_mse, normal_mse, thresh)
        marker = " <- current" if thresh == current else ""
        print(f"{thresh:>10} {m['tp']:>6} {m['fp']:>6} {m['tn']:>6} {m['fn']:>6} "
              f"{m['precision']:>9.1%} {m['recall']:>7.1%} {m['fpr']:>7.2%} {m['accuracy']:>8.1%}{marker}")

    print("\nChange it via: FLOW_ANOMALY_THRESHOLD=<value> (no retraining needed, takes effect immediately).")


if __name__ == "__main__":
    main()
