#!/usr/bin/env python3
"""
test_pipeline.py
================
Comprehensive Automated Test Suite covering all 6 Problem Statement Threat Classes:
a. Volumetric / Protocol DDoS
b. Botnet C2 Beaconing (Periodicity & IAT Variance)
c. DGA Domains & DNS Tunnelling
d. Encrypted Malware Sessions (JA3/JA4)
e. Reconnaissance & Port Scanning (Fan-Out)
f. Data Exfiltration
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "inference")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "ingest")))

from feature_extractor import (
    calculate_shannon_entropy,
    extract_dns_features,
    extract_conn_features,
    lookup_ja3,
    BeaconingTracker,
    ReconScanTracker,
)
from model_trainer import train_dga_detector, train_flow_anomaly_detector
from stream_processor import ComprehensiveThreatEngine


class TestComprehensiveThreatDetector(unittest.TestCase):

    def test_01_shannon_entropy(self):
        self.assertEqual(calculate_shannon_entropy("aaaaaaa"), 0.0)
        self.assertGreater(calculate_shannon_entropy("q7w8e9r0t1y2u3i4o5p"), 3.5)
        self.assertLess(calculate_shannon_entropy("google"), 2.5)

    def test_02_dns_and_tunneling(self):
        # DGA domain
        dga_rec = {"query": "x8f2k9a1z90q.cc", "qtype_name": "A"}
        feats = extract_dns_features(dga_rec)
        self.assertEqual(feats["tld"], "cc")
        self.assertEqual(feats["is_suspicious_tld"], 1)
        self.assertGreater(feats["entropy"], 3.0)

        # DNS Tunneling exfiltration record
        hex_payload = "0123456789abcdef" * 3
        tunnel_rec = {"query": f"data.{hex_payload}.c2tunnel.org", "qtype_name": "TXT"}
        tunnel_feats = extract_dns_features(tunnel_rec)
        self.assertTrue(tunnel_feats["is_tunnel_candidate"])
        self.assertIn("TXT", tunnel_feats["tunnel_reason"])

    def test_03_ja3_malware_signatures(self):
        match = lookup_ja3("a0e9f5d64349fb13191bc781f81f42e1")
        self.assertIsNotNone(match)
        self.assertEqual(match["family"], "Cobalt Strike Beacon")

        sliver_match = lookup_ja3("72a589da586844d7f0818ce684948eea")
        self.assertIsNotNone(sliver_match)
        self.assertEqual(sliver_match["family"], "Sliver C2 Agent")

    def test_04_data_exfiltration(self):
        exfil_conn = {
            "duration": 4.5,
            "orig_bytes": 50000000,
            "resp_bytes": 150,
            "orig_pkts": 35000,
            "resp_pkts": 4,
            "conn_state": "SF",
        }
        feats = extract_conn_features(exfil_conn)
        self.assertTrue(feats["is_exfiltration"])
        self.assertGreater(feats["byte_ratio"], 100000)

    def test_05_volumetric_ddos(self):
        syn_flood = {
            "duration": 0.01,
            "orig_bytes": 0,
            "resp_bytes": 0,
            "orig_pkts": 200,
            "resp_pkts": 0,
            "conn_state": "S0",
            "proto": "tcp",
        }
        feats = extract_conn_features(syn_flood)
        self.assertTrue(feats["is_ddos_candidate"])
        self.assertEqual(feats["ddos_subclass"], "TCP_SYN_FLOOD")

    def test_06_botnet_c2_beaconing(self):
        tracker = BeaconingTracker()
        src = "192.168.1.33"
        dst = "185.220.101.5"
        port = 443
        
        # Feed 5 pulses strictly every 10.0 seconds
        alerts = []
        for i in range(6):
            ts = 1000.0 + (i * 10.0)
            res = tracker.observe(src, dst, port, ts)
            if res:
                alerts.append(res)

        self.assertGreater(len(alerts), 0)
        self.assertAlmostEqual(alerts[-1]["mean_interval_sec"], 10.0, places=1)
        self.assertLess(alerts[-1]["jitter_cv"], 0.05)

    def test_07_recon_port_scanning(self):
        tracker = ReconScanTracker(window_sec=30.0)
        src = "192.168.1.99"
        target = "192.168.1.50"
        
        alert = None
        # Scan 15 ports
        for p in range(1, 16):
            res = tracker.observe(src, target, p, 1000.0 + (p * 0.1))
            if res:
                alert = res
                
        self.assertIsNotNone(alert)
        self.assertEqual(alert["scan_type"], "VERTICAL_PORT_SCAN")
        self.assertGreaterEqual(alert["unique_ports_scanned"], 12)

    def test_08_train_models(self):
        dga_clf = train_dga_detector()
        self.assertIsNotNone(dga_clf)
        flow_iso = train_flow_anomaly_detector()
        self.assertIsNotNone(flow_iso)

    def test_09_end_to_end_engine(self):
        engine = ComprehensiveThreatEngine()

        # DGA
        a_dga = engine.evaluate_dns({"query": "zk918fm021a8c90xz.cc", "qtype_name": "A"})
        self.assertIsNotNone(a_dga)
        self.assertEqual(a_dga["threat_class"], "DGA_DOMAIN")

        # DNS Tunneling
        a_tun = engine.evaluate_dns({"query": "data.abcdef0123456789abcdef012345.c2.cc", "qtype_name": "TXT"})
        self.assertIsNotNone(a_tun)
        self.assertEqual(a_tun["threat_class"], "DNS_TUNNELING_EXFIL")

        # JA3
        a_ja3 = engine.evaluate_ssl({"ja3": "a0e9f5d64349fb13191bc781f81f42e1"})
        self.assertIsNotNone(a_ja3)
        self.assertEqual(a_ja3["threat_class"], "MALICIOUS_JA3_FINGERPRINT")

        # Exfiltration
        a_exfil = engine.evaluate_conn({"orig_bytes": 45000000, "resp_bytes": 100, "duration": 5.0}, ts=100.0)
        self.assertIsNotNone(a_exfil)
        self.assertEqual(a_exfil["threat_class"], "DATA_EXFILTRATION")

        # Benign check
        self.assertIsNone(engine.evaluate_dns({"query": "www.google.com"}))
        self.assertIsNone(engine.evaluate_ssl({"ja3": "cd08e31494f9531f491fc72642953f76", "server_name": "google.com"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
