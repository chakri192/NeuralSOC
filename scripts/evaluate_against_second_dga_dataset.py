#!/usr/bin/env python3
"""evaluate_against_second_dga_dataset.py -- do the DGA CNN's real numbers
against benchmarks/real_dga_domains.csv hold up against a SECOND,
independently-sourced real dataset, or are they an artifact of that one
benchmark's specific domain generation (docs/PATH_TO_10_OUT_OF_10.md's
Phase 10)?

benchmarks/real_dga_domains_umudga.csv is built from UMUDGA (Zago, Gil
Perez, Martinez Perez, "UMUDGA: A dataset for profiling algorithmically
generated domain names in botnet detection," Data in Brief, 2020,
https://doi.org/10.1016/j.dib.2020.105400; dataset itself:
https://doi.org/10.17632/y8ph45msv8.1, MIT licensed) -- genuinely
different construction from the first dataset's Cucchiarelli et al. 2021
methodology (which observed real DGA traffic via the Netlab Opendata
Project): UMUDGA instead EXECUTES 50 real malware families' actual DGA
implementations in a controlled environment to generate their real
algorithmic output. Same real malware, a different way of obtaining real
samples of what it actually generates -- exactly the kind of methodological
independence needed to check the first benchmark's numbers aren't an
artifact of its own specific sampling.

Two honest, disclosed limitations in how this second dataset was built,
neither hidden:

1. UMUDGA's Mendeley Data listing exposes 206 file folders (one cluster
   per malware family: generator source, then domain lists at several
   size tiers) but its PUBLIC API never exposes the family NAME each
   folder corresponds to -- only one family (Locky) was identifiable at
   all, via a distinctively-named build artifact ("LockyDGA.exe") sitting
   in its folder. Rather than guess the other 50 families' real names and
   risk mislabeling a well-known malware family incorrectly (worse than
   not labeling it at all), each of the 51 domain-list folders found is
   treated as its own anonymous-but-reproducible group
   ("umudga_group_NN"), traceable back to the exact Mendeley folder it
   came from via benchmarks/umudga_group_manifest.csv. This means the
   per-group breakdown below can still show "the CNN completely misses
   whatever algorithm produced this specific, real, malware-executed
   output" without asserting a specific malware family name this project
   never actually verified.
2. UMUDGA's own benign side (1 million FQDNs) is NOT real registered
   domains -- it's built from the Leipzig Corpora's English-language
   word list (Wikipedia, 2016), i.e. plausible-looking word combinations,
   not verified-real, currently-registered websites. Since the roadmap's
   goal here is confirming real-world generalization, not adding a
   second synthetic-adjacent signal, the benign side of this dataset
   comes from Tranco instead (Pochat et al., a research-grade top-sites
   ranking designed to resist the manipulation concerns raised against
   Alexa; https://tranco-list.eu, list ID K9QPW, captured 2026-09-01) --
   real, currently-popular, currently-registered domains, and a
   genuinely different benign source from the first dataset's
   Alexa-derived one, not just a different malicious source.

Verified independence directly: only 21 of this dataset's 30,600 domains
exactly match a domain already in benchmarks/real_dga_domains.csv (0.07%,
consistent with coincidental short-string collisions, not reused data).

Runs the exact same production code path as
evaluate_against_real_dga_dataset.py (the live DeepLearningEngine CNN via
inference/models.py, and the rule-based entropy fallback via
inference/rules.py) and reports the same accuracy/precision/recall/FPR
breakdown, plus a regression gate: benchmarks/dga_second_dataset_baseline.json
records each group's CNN recall as of the last deliberate retrain,
independent of (and in addition to) the first dataset's own baseline --
either one regressing fails CI.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_against_second_dga_dataset.py
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_against_second_dga_dataset.py --limit 2000
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_against_second_dga_dataset.py --update-baseline
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

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_dga_domains_umudga.csv")
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "dga_second_dataset_baseline.json")
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
    """Mirrors evaluate_against_real_dga_dataset.py's identical helper --
    the entropy fallback rule, not the CNN (scored separately below)."""
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


def _write_baseline(cnn_metrics, group_stats):
    baseline = {
        "overall": {
            "precision": cnn_metrics["precision"],
            "recall": cnn_metrics["recall"],
            "fpr": cnn_metrics["fpr"],
            "accuracy": cnn_metrics["accuracy"],
        },
        "group_recall": {
            group: s["cnn_caught"] / s["total"] if s["total"] else 0.0
            for group, s in group_stats.items()
        },
    }
    with open(BASELINE_PATH, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
        f.write("\n")
    return baseline


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=None, help="Only evaluate the first N rows (default: all)")
    parser.add_argument("--update-baseline", action="store_true",
                         help="Overwrite benchmarks/dga_second_dataset_baseline.json with this run's numbers "
                              "(only after a deliberate retrain, not to silence a real regression)")
    args = parser.parse_args()

    print(f"[*] Loading {DATASET_PATH}...")
    rows = _load_dataset(args.limit)
    n_dga = sum(1 for is_dga, _, _ in rows if is_dga)
    n_legit = len(rows) - n_dga
    print(f"[*] {len(rows)} real domains loaded ({n_dga} real malware-executed DGA output, "
          f"{n_legit} real Tranco-ranked benign)\n")

    print("[*] Loading the live DGA CNN (models/cnn_dga.pt)...")
    engine = DeepLearningEngine(start_verifier=False)

    cnn_tp = cnn_fp = cnn_tn = cnn_fn = 0
    rule_tp = rule_fp = rule_tn = rule_fn = 0
    combined_tp = combined_fp = combined_tn = combined_fn = 0
    group_stats = defaultdict(lambda: {"total": 0, "cnn_caught": 0, "combined_caught": 0})

    print("[*] Scoring every domain through the real detection path...")
    for i, (is_dga, group, domain) in enumerate(rows):
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
            group_stats[group]["total"] += 1
            group_stats[group]["cnn_caught"] += int(cnn_flagged)
            group_stats[group]["combined_caught"] += int(either_flagged)
        else:
            cnn_fp += int(cnn_flagged)
            cnn_tn += int(not cnn_flagged)
            rule_fp += int(rule_flagged)
            rule_tn += int(not rule_flagged)
            combined_fp += int(either_flagged)
            combined_tn += int(not either_flagged)

        if (i + 1) % 5000 == 0:
            print(f"    ...{i + 1}/{len(rows)}")

    cnn_metrics = _confusion(cnn_tp, cnn_fp, cnn_tn, cnn_fn)
    rule_metrics = _confusion(rule_tp, rule_fp, rule_tn, rule_fn)
    combined_metrics = _confusion(combined_tp, combined_fp, combined_tn, combined_fn)

    print("\n" + "=" * 72)
    print("RESULTS -- against UMUDGA real malware-executed DGA output + real Tranco domains")
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
    print("Per-group recall (CNN vs. combined) -- each group is one real UMUDGA malware")
    print("family's actual DGA output; see benchmarks/umudga_group_manifest.csv for the")
    print("exact Mendeley source folder behind each anonymized group id")
    print("-" * 72)
    print(f"{'Group':<20} {'N':>6} {'CNN caught':>12} {'Combined caught':>16}")
    for group in sorted(group_stats.keys()):
        s = group_stats[group]
        cnn_pct = s["cnn_caught"] / s["total"] if s["total"] else 0.0
        combined_pct = s["combined_caught"] / s["total"] if s["total"] else 0.0
        print(f"{group:<20} {s['total']:>6} {cnn_pct:>11.1%} {combined_pct:>15.1%}")

    print("\nDataset: benchmarks/real_dga_domains_umudga.csv -- malicious domains from UMUDGA "
          "(Zago et al. 2020, https://doi.org/10.17632/y8ph45msv8.1, MIT licensed, real malware "
          "DGA implementations executed in a controlled environment), benign domains from Tranco "
          "(https://tranco-list.eu, list ID K9QPW) -- both independent of the first dataset's "
          "Cucchiarelli et al. 2021 / Alexa sourcing.")

    if args.update_baseline:
        baseline = _write_baseline(cnn_metrics, group_stats)
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
    print(f"REGRESSION CHECK vs. baseline (fails if any group's recall drops > {REGRESSION_THRESHOLD_POINTS:.0f} points)")
    print("-" * 72)
    regressions = []
    for group in sorted(group_stats.keys()):
        s = group_stats[group]
        current_recall = (s["cnn_caught"] / s["total"] if s["total"] else 0.0) * 100
        baseline_recall = baseline.get("group_recall", {}).get(group)
        if baseline_recall is None:
            print(f"  {group:<20} {current_recall:>6.1f}%  (new group, no baseline yet)")
            continue
        baseline_recall_pct = baseline_recall * 100
        delta = current_recall - baseline_recall_pct
        flag = ""
        if delta < -REGRESSION_THRESHOLD_POINTS:
            flag = "  <-- REGRESSION"
            regressions.append((group, baseline_recall_pct, current_recall))
        print(f"  {group:<20} baseline={baseline_recall_pct:>6.1f}%  current={current_recall:>6.1f}%  "
              f"delta={delta:+6.1f}{flag}")

    overall_delta = (cnn_metrics["recall"] - baseline["overall"]["recall"]) * 100
    print(f"\n  Overall recall: baseline={baseline['overall']['recall']:.1%}  "
          f"current={cnn_metrics['recall']:.1%}  delta={overall_delta:+.1f}pts")

    if regressions:
        print(f"\n[!] {len(regressions)} group regression(s) beyond {REGRESSION_THRESHOLD_POINTS:.0f} points:")
        for group, before, after in regressions:
            print(f"    {group}: {before:.1f}% -> {after:.1f}%")
        print("[!] If this is expected (a deliberate trade-off from a real retrain), "
              "re-run with --update-baseline to accept it.")
        return 1

    print("\n[+] No group regressions beyond threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
