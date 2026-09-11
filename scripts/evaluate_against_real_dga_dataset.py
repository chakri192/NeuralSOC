#!/usr/bin/env python3
"""evaluate_against_real_dga_dataset.py -- the answer to "has this ever
been tested against real attack traffic, or only your own simulator?"

benchmarks/real_dga_domains.csv is a genuine, published research dataset
(Cucchiarelli et al., Expert Systems with Applications, 2021 --
https://doi.org/10.1016/j.eswa.2020.114551), not synthetic data this
project generated for itself: 25 real malware families' actual
DGA-generated domains (sourced from the Netlab Opendata Project's
observed traffic) alongside real Alexa-ranked benign domains. Free for
research use per the dataset's own README; this script only reads it.

Runs the exact same code path production traffic hits -- the live
DeepLearningEngine (CNN) via inference/models.py, and the rule-based
entropy fallback via inference/rules.py -- against every row, and
reports real accuracy/precision/recall/false-positive-rate, broken down
per real malware family, not one aggregate number that could hide a
family this completely misses.

Also acts as a regression gate: benchmarks/dga_family_recall_baseline.json
records each family's CNN recall as of the last deliberate retrain. Every
run compares against it and exits non-zero if any family's recall drops
by more than REGRESSION_THRESHOLD_POINTS -- this is exactly the check
that would have caught the vawtrak/conficker/pushdo recall regression
from the hybrid-model retrain automatically, instead of requiring a
manual re-run to notice. Pass --update-baseline after a deliberate
retrain to accept the new numbers as the baseline going forward.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_against_real_dga_dataset.py
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_against_real_dga_dataset.py --limit 2000
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_against_real_dga_dataset.py --update-baseline
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.features import extract_dns_features
from inference.models import DeepLearningEngine
from inference.rules import evaluate_rules

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_dga_domains.csv")
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "dga_family_recall_baseline.json")
REGRESSION_THRESHOLD_POINTS = 10.0


def _load_dataset(limit=None):
    rows = []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        for label, family, domain in csv.reader(f):
            rows.append((label.strip() == "dga", family.strip(), domain.strip()))
    if limit:
        rows = rows[:limit]
    return rows


def _rule_flags_as_dga(domain: str) -> bool:
    """Mirrors exactly how inference/rules.py's evaluate_rules() is
    actually invoked in production for a DNS event -- the entropy
    fallback rule, not the CNN (that's scored separately below)."""
    event = {"event_type": "dns", "query": domain, "qtype_name": "A"}
    features = extract_dns_features(event)
    detections = evaluate_rules(event, features)
    return any(d["rule_id"] == "RULE_DNS_DGA_FALLBACK" for d in detections)


def _confusion(tp, fp, tn, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "fpr": fpr, "f1": f1}


def _load_baseline():
    if not os.path.exists(BASELINE_PATH):
        return None
    with open(BASELINE_PATH, encoding="utf-8") as f:
        return json.load(f)


def _write_baseline(cnn_metrics, family_stats):
    baseline = {
        "overall": {
            "precision": cnn_metrics["precision"],
            "recall": cnn_metrics["recall"],
            "fpr": cnn_metrics["fpr"],
            "accuracy": cnn_metrics["accuracy"],
        },
        "family_recall": {
            family: s["cnn_caught"] / s["total"] if s["total"] else 0.0
            for family, s in family_stats.items()
        },
    }
    with open(BASELINE_PATH, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
        f.write("\n")
    return baseline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Only evaluate the first N rows (default: all)")
    parser.add_argument("--update-baseline", action="store_true",
                         help="Overwrite benchmarks/dga_family_recall_baseline.json with this run's numbers "
                              "(only after a deliberate retrain, not to silence a real regression)")
    args = parser.parse_args()

    print(f"[*] Loading {DATASET_PATH}...")
    rows = _load_dataset(args.limit)
    n_dga = sum(1 for is_dga, _, _ in rows if is_dga)
    n_legit = len(rows) - n_dga
    print(f"[*] {len(rows)} real domains loaded ({n_dga} real malware-family DGA, {n_legit} real Alexa-ranked benign)\n")

    print("[*] Loading the live DGA CNN (models/cnn_dga.pt)...")
    engine = DeepLearningEngine(start_verifier=False)

    cnn_tp = cnn_fp = cnn_tn = cnn_fn = 0
    rule_tp = rule_fp = rule_tn = rule_fn = 0
    combined_tp = combined_fp = combined_tn = combined_fn = 0
    family_stats = defaultdict(lambda: {"total": 0, "cnn_caught": 0, "combined_caught": 0})

    print("[*] Scoring every domain through the real detection path...")
    for i, (is_dga, family, domain) in enumerate(rows):
        cnn_flagged, prob, _ = engine.predict({}, domain)
        rule_flagged = _rule_flags_as_dga(domain)
        either_flagged = cnn_flagged or rule_flagged

        if is_dga:
            cnn_tp += int(cnn_flagged)
            cnn_fn += int(not cnn_flagged)
            rule_tp += int(rule_flagged)
            rule_fn += int(not rule_flagged)
            combined_tp += int(either_flagged)
            combined_fn += int(not either_flagged)
            family_stats[family]["total"] += 1
            family_stats[family]["cnn_caught"] += int(cnn_flagged)
            family_stats[family]["combined_caught"] += int(either_flagged)
        else:
            cnn_fp += int(cnn_flagged)
            cnn_tn += int(not cnn_flagged)
            rule_fp += int(rule_flagged)
            rule_tn += int(not rule_flagged)
            combined_fp += int(either_flagged)
            combined_tn += int(not either_flagged)

        if (i + 1) % 2000 == 0:
            print(f"    ...{i + 1}/{len(rows)}")

    cnn_metrics = _confusion(cnn_tp, cnn_fp, cnn_tn, cnn_fn)
    rule_metrics = _confusion(rule_tp, rule_fp, rule_tn, rule_fn)
    combined_metrics = _confusion(combined_tp, combined_fp, combined_tn, combined_fn)

    print("\n" + "=" * 72)
    print("RESULTS -- against real malware-family DGA domains + real Alexa domains")
    print("=" * 72)

    def _print_row(name, m, tp, fp, tn, fn):
        print(f"\n{name}")
        print(f"  Accuracy:  {m['accuracy']:.1%}    F1: {m['f1']:.3f}")
        print(f"  Precision: {m['precision']:.1%}   (of what it flagged, how much was really DGA)")
        print(f"  Recall:    {m['recall']:.1%}   (of real DGA domains, how many it caught)")
        print(f"  False-positive rate: {m['fpr']:.2%}   (real benign domains wrongly flagged)")
        print(f"  Confusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    _print_row("CNN only (DL_CNN_DGA)", cnn_metrics, cnn_tp, cnn_fp, cnn_tn, cnn_fn)
    _print_row("Entropy rule only (RULE_DNS_DGA_FALLBACK)", rule_metrics, rule_tp, rule_fp, rule_tn, rule_fn)
    _print_row("Combined (either fires)", combined_metrics, combined_tp, combined_fp, combined_tn, combined_fn)

    print("\n" + "-" * 72)
    print("Per-family recall (CNN vs. combined) -- real malware families, not synthetic")
    print("-" * 72)
    print(f"{'Family':<20} {'N':>6} {'CNN caught':>12} {'Combined caught':>16}")
    for family in sorted(family_stats.keys()):
        s = family_stats[family]
        cnn_pct = s["cnn_caught"] / s["total"] if s["total"] else 0.0
        combined_pct = s["combined_caught"] / s["total"] if s["total"] else 0.0
        print(f"{family:<20} {s['total']:>6} {cnn_pct:>11.1%} {combined_pct:>15.1%}")

    print("\nDataset: benchmarks/real_dga_domains.csv (Cucchiarelli et al. 2021, "
          "https://doi.org/10.1016/j.eswa.2020.114551) -- real malware-family DGA "
          "domains and real Alexa-ranked benign domains, not this project's own simulator.")

    if args.update_baseline:
        baseline = _write_baseline(cnn_metrics, family_stats)
        print(f"\n[+] Baseline updated: {BASELINE_PATH}")
        print(f"    Overall: precision={baseline['overall']['precision']:.1%} "
              f"recall={baseline['overall']['recall']:.1%} fpr={baseline['overall']['fpr']:.2%}")
        return 0

    baseline = _load_baseline()
    if baseline is None:
        print(f"\n[!] No baseline found at {BASELINE_PATH} -- run with --update-baseline to create one. "
              "Skipping regression check.")
        return 0

    print("\n" + "-" * 72)
    print(f"REGRESSION CHECK vs. baseline (fails if any family's recall drops > {REGRESSION_THRESHOLD_POINTS:.0f} points)")
    print("-" * 72)
    regressions = []
    for family in sorted(family_stats.keys()):
        s = family_stats[family]
        current_recall = (s["cnn_caught"] / s["total"] if s["total"] else 0.0) * 100
        baseline_recall = baseline.get("family_recall", {}).get(family)
        if baseline_recall is None:
            print(f"  {family:<20} {current_recall:>6.1f}%  (new family, no baseline yet)")
            continue
        baseline_recall_pct = baseline_recall * 100
        delta = current_recall - baseline_recall_pct
        flag = ""
        if delta < -REGRESSION_THRESHOLD_POINTS:
            flag = "  <-- REGRESSION"
            regressions.append((family, baseline_recall_pct, current_recall))
        print(f"  {family:<20} baseline={baseline_recall_pct:>6.1f}%  current={current_recall:>6.1f}%  "
              f"delta={delta:+6.1f}{flag}")

    overall_delta = (cnn_metrics["recall"] - baseline["overall"]["recall"]) * 100
    print(f"\n  Overall recall: baseline={baseline['overall']['recall']:.1%}  "
          f"current={cnn_metrics['recall']:.1%}  delta={overall_delta:+.1f}pts")

    if regressions:
        print(f"\n[!] {len(regressions)} family regression(s) beyond {REGRESSION_THRESHOLD_POINTS:.0f} points:")
        for family, before, after in regressions:
            print(f"    {family}: {before:.1f}% -> {after:.1f}%")
        print("[!] If this is expected (a deliberate trade-off from a real retrain), "
              "re-run with --update-baseline to accept it.")
        return 1

    print("\n[+] No family regressions beyond threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
