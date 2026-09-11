#!/usr/bin/env python3
"""calibrate_dga_threshold.py -- shows what DGA_CLASSIFICATION_THRESHOLD
(inference/models.py) actually costs and buys, at every candidate value,
against the same real held-out benchmark
scripts/evaluate_against_real_dga_dataset.py uses.

The threshold is a config value (env var DGA_CLASSIFICATION_THRESHOLD,
default 0.85), not something that requires retraining to change. This
script exists so picking a different operating point -- more recall,
tolerating more false positives; or more precision, tolerating missed
detections -- is an informed choice against real measured numbers, not a
guess.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/calibrate_dga_threshold.py
    PYTHONPATH=. venv/bin/python3 scripts/calibrate_dga_threshold.py --limit 2000
"""
import argparse
import csv
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.models import DeepLearningEngine

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_dga_domains.csv")

CANDIDATE_THRESHOLDS = [0.50, 0.70, 0.85, 0.90, 0.95, 0.97, 0.99, 0.995, 0.999, 0.9999]


def _load_dataset(limit=None):
    rows = []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        for label, family, domain in csv.reader(f):
            rows.append((label.strip() == "dga", domain.strip()))
    if limit:
        rows = rows[:limit]
    return rows


def _confusion_at(dga_probs, benign_probs, thresh):
    tp = sum(1 for p in dga_probs if p > thresh)
    fn = len(dga_probs) - tp
    fp = sum(1 for p in benign_probs if p > thresh)
    tn = len(benign_probs) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "fpr": fpr, "accuracy": accuracy}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Only evaluate the first N rows (default: all)")
    args = parser.parse_args()

    print(f"[*] Loading {DATASET_PATH}...")
    rows = _load_dataset(args.limit)
    print(f"[*] {len(rows)} real domains loaded\n")

    print("[*] Loading the live DGA model (models/cnn_dga.pt) -- scoring raw probabilities, "
          "not gated by the currently-configured threshold...")
    engine = DeepLearningEngine(start_verifier=False)

    dga_probs, benign_probs = [], []
    for i, (is_dga, domain) in enumerate(rows):
        _, prob, _ = engine.predict({}, domain)
        (dga_probs if is_dga else benign_probs).append(prob)
        if (i + 1) % 2000 == 0:
            print(f"    ...{i + 1}/{len(rows)}")

    current = float(os.getenv("DGA_CLASSIFICATION_THRESHOLD", "0.85"))
    print(f"\nCurrently configured DGA_CLASSIFICATION_THRESHOLD: {current}")
    print(f"(set the env var and re-run this script to see a different value's real cost/benefit)\n")

    print(f"{'threshold':>10} {'TP':>6} {'FP':>6} {'TN':>6} {'FN':>6} {'precision':>10} {'recall':>8} {'fpr':>8} {'accuracy':>9}")
    thresholds = sorted(set(CANDIDATE_THRESHOLDS) | {current})
    for thresh in thresholds:
        m = _confusion_at(dga_probs, benign_probs, thresh)
        marker = " <- current" if thresh == current else ""
        print(f"{thresh:>10} {m['tp']:>6} {m['fp']:>6} {m['tn']:>6} {m['fn']:>6} "
              f"{m['precision']:>9.1%} {m['recall']:>7.1%} {m['fpr']:>7.2%} {m['accuracy']:>8.1%}{marker}")

    print("\nHigher threshold -> fewer false positives, more missed detections (higher precision, lower recall).")
    print("Lower threshold -> more detections caught, more false alarms (lower precision, higher recall).")
    print("Change it via: DGA_CLASSIFICATION_THRESHOLD=<value> (no retraining needed, takes effect immediately).")


if __name__ == "__main__":
    main()
