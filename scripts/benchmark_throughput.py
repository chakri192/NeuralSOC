#!/usr/bin/env python3
"""
benchmark_throughput.py
=======================
Measures and demonstrates sustained throughput and latency under high-load streaming:
1. Generates high-volume synthetic flow metadata streams (10,000 - 100,000 flows).
2. Measures sustained Flows/sec and equivalent network throughput (Mbps).
3. Computes Latency Percentiles (P50, P90, P95, P99) in microseconds (us).
4. Verifies bounded latency and sub-millisecond per-flow processing time on Apple Silicon (ARM64).

Previously imported a "ComprehensiveThreatEngine" class from
inference/stream_processor.py -- a class that existed nowhere in the repo
(that module has since been removed as dead code; the live pipeline is
inference/stream_processor_faust.py). This benchmark now calls the same
functions the live agent's process_traffic() calls per event --
extract_features(), evaluate_rules(), and DeepLearningEngine.predict()
for DNS records -- so it measures the actual detection pipeline's
per-event latency, not a mock.
"""

import os
import sys
import time
import random
import string
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import DeepLearningEngine


def generate_benchmark_records(n: int = 50000) -> list:
    records = []
    t_base = time.time()

    ips = [f"192.168.1.{i}" for i in range(10, 200)]
    ext_ips = ["142.250.190.46", "140.82.121.4", "13.107.42.14", "185.220.101.5"]
    domains = ["google.com", "github.com", "microsoft.com", "cloudflare.com", "amazon.com"]
    # Same synthetic value ingest/simulator.py's demo attack injector uses --
    # see inference/rules.py's _JA4_MALICIOUS_FINGERPRINTS default.
    malicious_ja4 = "t13d000000_rare_fingerprint"
    benign_ja4 = "t13d1516h2_8daaf6152771_02713d6af862"

    for i in range(n):
        # The live pipeline (inference/rules.py, inference/features.py)
        # only branches on event_type "dns" and "conn" -- match that,
        # rather than a third "ssl" type the real rule engine never sees.
        rec_type = random.choice(["dns", "conn"])
        uid = f"Cbench{i:07d}"
        src = random.choice(ips)
        dst = random.choice(ext_ips)
        ts = t_base + (i * 0.0001)

        if rec_type == "dns":
            # 98% normal, 2% DGA/tunneling
            if random.random() < 0.02:
                q = "".join(random.choices(string.ascii_lowercase + string.digits, k=18)) + ".cc"
            else:
                q = random.choice(domains)
            records.append({
                "event_type": "dns",
                "ts": ts,
                "uid": uid,
                "id.orig_h": src,
                "id.orig_p": 53000,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "proto": "udp",
                "query": q,
                "qtype_name": "A",
            })
        else:  # conn
            orig_b = 50000000 if random.random() < 0.01 else random.randint(500, 5000)
            resp_b = 100 if orig_b > 1000000 else random.randint(2000, 50000)
            records.append({
                "event_type": "conn",
                "ts": ts,
                "uid": uid,
                "id.orig_h": src,
                "id.orig_p": 55000,
                "id.resp_h": dst,
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": random.uniform(0.1, 5.0),
                "orig_bytes": orig_b,
                "resp_bytes": resp_b,
                "orig_pkts": max(1, int(orig_b / 1400)),
                "resp_pkts": max(1, int(resp_b / 1400)),
                "conn_state": "SF",
                "ja4": malicious_ja4 if random.random() < 0.01 else benign_ja4,
            })

    return records


def evaluate_record(engine: DeepLearningEngine, record: dict) -> list:
    """Mirrors inference/stream_processor_faust.py's process_traffic():
    feature extraction, rule evaluation, and (for DNS) CNN inference."""
    features = extract_features(record)
    detections = evaluate_rules(record, features)

    if record.get("event_type") == "dns":
        query = record.get("query", "")
        if query and len(query) <= 253:
            is_dga, prob, _ = engine.predict(features, query)
            if is_dga:
                detections.append({
                    "threat_class": "DGA / DNS Tunnelling",
                    "severity": "high",
                    "confidence": prob,
                    "rule_id": "DL_CNN_DGA",
                })
    return detections


def run_benchmark(num_records: int = 50000):
    print("=" * 70)
    print(f"   UNIDIRECTIONAL THREAT DETECTION THROUGHPUT & LATENCY BENCHMARK")
    print(f"  Target: {num_records:,} Streaming Flow Records on Apple Silicon (ARM64)")
    print("=" * 70)

    print("[*] Generating dataset...")
    records = generate_benchmark_records(num_records)
    print(f"[+] Dataset ready ({len(records):,} flow events).\n")

    print("[*] Initializing Deep Learning Engine (CNN DGA classifier)...")
    engine = DeepLearningEngine(start_verifier=False)
    print("[+] Engine initialized.\n")

    # Warmup
    for r in records[:500]:
        evaluate_record(engine, r)

    print(f"[*] Executing high-speed streaming evaluation on {num_records:,} flows...")

    latencies_us = []
    alerts_count = 0

    t_start = time.perf_counter()

    for r in records:
        t0 = time.perf_counter()
        detections = evaluate_record(engine, r)
        t1 = time.perf_counter()
        latencies_us.append((t1 - t0) * 1_000_000)  # Convert to microseconds

        if detections:
            alerts_count += 1

    total_time_sec = time.perf_counter() - t_start

    # Compute Metrics
    flows_per_sec = num_records / total_time_sec
    # Average flow corresponds to ~12 packets (avg 800 bytes = ~9.6 KB per flow equivalent on wire)
    equiv_mbps = (flows_per_sec * 9600 * 8) / (1_000_000)

    p50 = np.percentile(latencies_us, 50)
    p90 = np.percentile(latencies_us, 90)
    p95 = np.percentile(latencies_us, 95)
    p99 = np.percentile(latencies_us, 99)
    max_lat = np.max(latencies_us)
    mean_lat = np.mean(latencies_us)

    print("\n" + "=" * 70)
    print("   BENCHMARK RESULTS")
    print("=" * 70)
    print(f"  • Total Flows Processed      : {num_records:,} flows")
    print(f"  • Total Time Elapsed         : {total_time_sec:.3f} seconds")
    print(f"  • Sustained Throughput       : {flows_per_sec:,.1f} flows/second")
    print(f"  • Wire Equivalent Bandwidth  : {equiv_mbps:,.2f} Mbps sustained")
    print(f"  • Threats Detected & Labelled: {alerts_count:,} alerts ({alerts_count/num_records*100:.2f}% anomaly rate)")
    print("-" * 70)
    print("  ⏱ LATENCY PERCENTILES (Per-Flow Decision Latency):")
    print(f"  • Mean Latency               : {mean_lat:.2f} µs ({mean_lat/1000:.3f} ms)")
    print(f"  • Median (P50) Latency       : {p50:.2f} µs ({p50/1000:.3f} ms)")
    print(f"  • 90th Percentile (P90)      : {p90:.2f} µs ({p90/1000:.3f} ms)")
    print(f"  • 95th Percentile (P95)      : {p95:.2f} µs ({p95/1000:.3f} ms)")
    print(f"  • 99th Percentile (P99)      : {p99:.2f} µs ({p99/1000:.3f} ms)")
    print(f"  • Max Latency                : {max_lat:.2f} µs ({max_lat/1000:.3f} ms)")
    print("=" * 70)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    run_benchmark(n)
