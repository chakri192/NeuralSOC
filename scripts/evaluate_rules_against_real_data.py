#!/usr/bin/env python3
"""evaluate_rules_against_real_data.py -- the rule-based-detection
equivalent of scripts/evaluate_against_real_dga_dataset.py and
scripts/evaluate_flow_autoencoder_against_real_data.py: 4 of the 6
detection categories this platform claims (DDoS, C2 Beaconing,
Reconnaissance, Data Exfiltration) had never been run against real
attack data before this script existed -- every claim made about them
was against this repo's own synthetic simulator only.

benchmarks/real_rule_validation_dataset.csv is a sampled extract from
all 13 CTU-13 scenarios (Stratosphere IPS / CVUT, CC-BY,
https://www.stratosphereips.org/datasets-ctu13) -- real botnet-infected
host traffic and real confirmed-clean host traffic. Unlike the DGA/flow
retraining work, rule validation needs no train/test split: these are
fixed heuristics in inference/rules.py, not models fit to data, so
there's no leakage risk evaluating them against any real CTU-13 traffic,
including scenarios also used elsewhere in this repo for model training.

Runs the exact same evaluate_rules() production code every real event
hits, not a reimplementation. Two honest, disclosed limitations:

1. CTU-13's .binetflow (Argus) format reports TotPkts (both directions
   combined), not per-direction packet counts -- same limitation as
   scripts/evaluate_flow_autoencoder_against_real_data.py, and for the
   same reason (no separate orig_pkts field exists in this data).
2. Argus's State field uses TCP-flag notation (e.g. "S_" = SYN sent, no
   reply; "S_RA" = SYN sent, RST-ACK received), not Zeek's semantic
   conn_state labels ("S0", "REJ") the Reconnaissance and DDoS rules
   check for. _argus_state_to_zeek_conn_state() below is a best-effort
   translation for just those two categories, empirically checked
   against real packet-count distributions before being trusted (S_
   rows: mostly 1-7 total packets, consistent with "SYN sent, nothing
   back"; S_RA rows: mostly exactly 2, consistent with "SYN out,
   RST-ACK back") -- not a complete or authoritative Argus<->Zeek
   mapping, and anything it doesn't recognize maps to no match (the
   conservative default: an unmapped state can never accidentally
   satisfy conn_state == "S0" or == "REJ").

The Encrypted-Traffic Malware rule (JA4 fingerprinting) is NOT covered
here -- CTU-13's flow records have no TLS handshake data at all. That
needs a genuinely different real dataset (a real malicious JA3/JA4
fingerprint feed, e.g. Abuse.ch), not something already on disk.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/evaluate_rules_against_real_data.py
"""
import csv
import os
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.rules import evaluate_rules

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_rule_validation_dataset.csv")

# Only rules this dataset can actually exercise -- see module docstring
# for why JA4/DGA aren't here (JA4 needs different data; DGA is a "dns"
# event type rule, already covered by evaluate_against_real_dga_dataset.py).
RULE_TO_THREAT_CLASS = {
    "RULE_DDOS_VOLUMETRIC": "DDoS",
    "RULE_C2_HEARTBEAT": "C2 Beaconing",
    "RULE_RECON_PORT_SCAN": "Reconnaissance",
    "RULE_CONN_EXFIL": "Data Exfiltration",
}


def _argus_state_to_zeek_conn_state(state: str) -> str:
    """See module docstring for the empirical basis and limitations."""
    if not state or "_" not in state:
        return ""
    origin, dest = state.split("_", 1)
    if not dest:
        return "S0"
    if origin.startswith("S") and "R" in dest:
        return "REJ"
    return ""


def _load_dataset():
    rows = []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "is_botnet": row["label"] == "botnet",
                "scenario": row["scenario"],
                "dport": int(row["dport"]),
                "state": row["state"],
                "orig_bytes": float(row["orig_bytes"]),
                "resp_bytes": float(row["resp_bytes"]),
                "tot_pkts": float(row["tot_pkts"]),
            })
    return rows


def _confusion(tp, fp, tn, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "fpr": fpr}


def main():
    print(f"[*] Loading {DATASET_PATH}...")
    rows = _load_dataset()
    n_botnet = sum(1 for r in rows if r["is_botnet"])
    n_normal = len(rows) - n_botnet
    print(f"[*] {len(rows)} real flows loaded ({n_botnet} real Botnet, {n_normal} real Normal) "
          f"across {len(set(r['scenario'] for r in rows))} real CTU-13 scenarios\n")

    counts = {rule_id: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for rule_id in RULE_TO_THREAT_CLASS}

    for row in rows:
        zeek_state = _argus_state_to_zeek_conn_state(row["state"])
        event = {
            "event_type": "conn",
            "id.resp_p": row["dport"],
            "conn_state": zeek_state,
            "orig_pkts": row["tot_pkts"],
        }
        features = {"orig_bytes": row["orig_bytes"], "resp_bytes": row["resp_bytes"]}
        fired_rule_ids = {d["rule_id"] for d in evaluate_rules(event, features)}

        for rule_id in RULE_TO_THREAT_CLASS:
            fired = rule_id in fired_rule_ids
            if row["is_botnet"]:
                counts[rule_id]["tp" if fired else "fn"] += 1
            else:
                counts[rule_id]["fp" if fired else "tn"] += 1

    print("=" * 72)
    print("RESULTS -- rule-based detectors against real CTU-13 botnet/normal flows")
    print("=" * 72)
    for rule_id, threat_class in RULE_TO_THREAT_CLASS.items():
        c = counts[rule_id]
        m = _confusion(c["tp"], c["fp"], c["tn"], c["fn"])
        print(f"\n{rule_id} ({threat_class})")
        print(f"  Accuracy:  {m['accuracy']:.1%}")
        print(f"  Precision: {m['precision']:.1%}   (of what it flagged, how much was really Botnet)")
        print(f"  Recall:    {m['recall']:.1%}   (of real Botnet flows, how many it caught)")
        print(f"  False-positive rate: {m['fpr']:.2%}   (real Normal flows wrongly flagged)")
        print(f"  Confusion: TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}")

    print("\n" + "-" * 72)
    print("Per-scenario recall (each rule vs. real Botnet flows in that scenario)")
    print("-" * 72)
    by_scenario = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # scenario -> rule_id -> [caught, total]
    for row in rows:
        if not row["is_botnet"]:
            continue
        zeek_state = _argus_state_to_zeek_conn_state(row["state"])
        event = {"event_type": "conn", "id.resp_p": row["dport"], "conn_state": zeek_state, "orig_pkts": row["tot_pkts"]}
        features = {"orig_bytes": row["orig_bytes"], "resp_bytes": row["resp_bytes"]}
        fired_rule_ids = {d["rule_id"] for d in evaluate_rules(event, features)}
        for rule_id in RULE_TO_THREAT_CLASS:
            by_scenario[row["scenario"]][rule_id][1] += 1
            if rule_id in fired_rule_ids:
                by_scenario[row["scenario"]][rule_id][0] += 1

    header = f"{'Scenario':>10}" + "".join(f"{rid:>22}" for rid in RULE_TO_THREAT_CLASS)
    print(header)
    for scenario in sorted(by_scenario.keys(), key=lambda s: int(s)):
        line = f"{scenario:>10}"
        for rule_id in RULE_TO_THREAT_CLASS:
            caught, total = by_scenario[scenario][rule_id]
            pct = caught / total if total else 0.0
            line += f"{f'{caught}/{total} ({pct:.0%})':>22}"
        print(line)

    print("\nDataset: benchmarks/real_rule_validation_dataset.csv (CTU-13, all 13 scenarios, "
          "Stratosphere IPS / CVUT, CC-BY, https://www.stratosphereips.org/datasets-ctu13) -- "
          "real botnet-infected host traffic and real confirmed-clean host traffic, not this "
          "project's own simulator.")


if __name__ == "__main__":
    main()
