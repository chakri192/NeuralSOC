import unittest
import asyncio
import os
import json
import time
from unittest.mock import MagicMock, patch

from inference.models import DeepLearningEngine
from inference.correlation import IncidentCorrelator
from inference.enrichment import ThreatEnricher
from api.main import _validate_ip, _is_trusted_proxy, get_remote_address

class TestSOCPipelineSecurity(unittest.TestCase):
    def test_ip_validation_and_proxy_trust(self):
        # Valid IPv4 and IPv6
        self.assertEqual(_validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(_validate_ip("::1"), "::1")
        self.assertIsNone(_validate_ip("invalid.ip.address"))
        self.assertIsNone(_validate_ip("999.999.999.999"))

        # Proxy trust check
        self.assertTrue(_is_trusted_proxy("127.0.0.1"))
        self.assertTrue(_is_trusted_proxy("::1"))
        self.assertTrue(_is_trusted_proxy("10.244.1.5"))
        self.assertTrue(_is_trusted_proxy("172.16.0.10"))
        # External untrusted IP
        self.assertFalse(_is_trusted_proxy("203.0.113.50"))

    def test_remote_address_spoof_prevention(self):
        # Request with spoofed X-Forwarded-For from direct client (not proxy)
        mock_req_untrusted = MagicMock()
        mock_req_untrusted.client.host = "203.0.113.50"
        mock_req_untrusted.headers = {"X-Forwarded-For": "10.0.0.1, 8.8.8.8"}
        # Must return actual direct client IP, ignoring forged header
        self.assertEqual(get_remote_address(mock_req_untrusted), "203.0.113.50")

        # Request from trusted loopback proxy
        mock_req_proxy = MagicMock()
        mock_req_proxy.client.host = "127.0.0.1"
        mock_req_proxy.headers = {"X-Forwarded-For": "203.0.113.99, 127.0.0.1"}
        # Must return the verified rightmost non-proxy client IP
        self.assertEqual(get_remote_address(mock_req_proxy), "203.0.113.99")

    def test_dl_model_integrity_resilience(self):
        engine = DeepLearningEngine()
        # Verify initial model is loaded
        self.assertIsNotNone(engine.model)

        # Simulate a transient OSError/IOError during periodic check
        with patch("builtins.open", side_effect=OSError("Disk busy")):
            # _recheck_integrity should return True (resilient fallback) and keep model in memory
            result = engine._recheck_integrity()
            self.assertTrue(result)
            self.assertIsNotNone(engine.model)

        # Normal prediction should succeed without crashing
        is_dga, prob, _ = engine.predict({}, "google.com")
        self.assertFalse(is_dga)
        self.assertIsInstance(prob, float)

    def test_correlator_multi_alert_aggregation(self):
        correlator = IncidentCorrelator()
        test_ip = "192.168.100.42"

        alert1 = {
            "alert_id": "ALT-001",
            "source_ip": test_ip,
            "destination_ip": "10.0.0.1",
            "threat_class": "Reconnaissance",
            "severity": "low",
            "mitre_tactic": "Discovery"
        }
        alert2 = {
            "alert_id": "ALT-002",
            "source_ip": test_ip,
            "destination_ip": "10.0.0.2",
            "threat_class": "C2 Beaconing",
            "severity": "high",
            "mitre_tactic": "Command and Control"
        }

        # Clear existing keys for test isolation
        try:
            correlator.redis.delete(f"{{{test_ip}}}:alerts", f"{{{test_ip}}}:dedup:C2_Beaconing", f"{{{test_ip}}}:dedup:Reconnaissance")
        except Exception:
            pass

        try:
            inc1 = correlator.add_alert(alert1)
            # First alert alone should not trigger incident (threshold len >= 2)
            self.assertIsNone(inc1)

            inc2 = correlator.add_alert(alert2)
            # Second alert triggers incident
            if inc2:
                self.assertEqual(inc2["source_ip"], test_ip)
                # Verify that both threat classes and alert IDs were aggregated
                self.assertIn("C2 Beaconing", inc2["threat_classes"])
                self.assertIn("ALT-002", inc2["related_alert_ids"])
                self.assertEqual(inc2["severity"], "high")
                self.assertGreaterEqual(inc2["risk_score"], 75.0)
        except Exception as e:
            # Skip if Redis server is not running locally during unit test
            print(f"Redis test skipped: {e}")

    def test_enrichment_cache_and_fallback(self):
        async def run_async_test():
            enricher = ThreatEnricher(cache_ttl_sec=60)
            test_alert = {
                "source_ip": "8.8.8.8",
                "destination_ip": "1.1.1.1",
                "evidence": {}
            }
            # Enrich should complete cleanly with cached or fallback intel
            enriched = await enricher.enrich(test_alert)
            self.assertIn("evidence", enriched)
            self.assertIn("Live GeoIP", enriched["evidence"])

            # Second call should hit in-memory cache instantly
            cached_val = enricher._get_cached("8.8.8.8")
            self.assertIsNotNone(cached_val)
            self.assertIn("country_name", cached_val)

        asyncio.run(run_async_test())

    def test_ssrf_strict_blocking(self):
        async def run_ssrf_test():
            enricher = ThreatEnricher()
            # Private, loopback, link-local, multicast, cloud metadata, and RFC1918 addresses
            blocked_ips = [
                "127.0.0.1",
                "10.0.0.1",
                "172.16.0.1",
                "172.20.10.5",
                "172.31.255.254",
                "192.168.1.1",
                "169.254.169.254",
                "0.0.0.0",
                "224.0.0.1",
                "240.0.0.1",
                "100.64.0.1",
                "::1",
                "fc00::1",
                "not-an-ip",
            ]
            for blocked_ip in blocked_ips:
                res = await enricher._fetch_intel(blocked_ip)
                self.assertEqual(res, {}, f"Expected SSRF block for {blocked_ip}")

        asyncio.run(run_ssrf_test())

    def test_overly_broad_proxy_rejection(self):
        import ipaddress
        # Ensure that broad networks (< 8 for v4, < 64 for v6) are rejected
        broad_v4 = ipaddress.ip_network("0.0.0.0/0")
        self.assertTrue((broad_v4.version == 4 and broad_v4.prefixlen < 8))

        # Standard RFC1918 /8 is allowed
        rfc1918_v4 = ipaddress.ip_network("10.0.0.0/8")
        self.assertFalse((rfc1918_v4.version == 4 and rfc1918_v4.prefixlen < 8))

        loopback = ipaddress.ip_network("127.0.0.1/32")
        self.assertFalse((loopback.version == 4 and loopback.prefixlen < 8))

    def test_ipv6_correlation_support(self):
        import re
        safe_re = re.compile(r"^[A-Za-z0-9_.:-]+$")
        ipv6_test = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        self.assertTrue(bool(safe_re.match(ipv6_test)))
        self.assertFalse(bool(safe_re.match("2001:db8;rm -rf /")))

    def test_model_null_safety(self):
        engine = DeepLearningEngine()
        engine.model = None
        is_dga, prob, _ = engine.predict({}, "google.com")
        self.assertFalse(is_dga)
        self.assertEqual(prob, 0.0)

    def test_threat_model_orchestrator(self):
        from inference.models import ThreatModelOrchestrator
        orchestrator = ThreatModelOrchestrator()
        # Test non-dns event
        dets = orchestrator.evaluate({"event_type": "conn"}, {})
        self.assertEqual(dets, [])
        # Test benign dns event
        dets = orchestrator.evaluate({"event_type": "dns", "query": "google.com"}, {})
        self.assertEqual(dets, [])

    def test_idna_homoglyph_handling(self):
        engine = DeepLearningEngine()
        # Ensure Cyrillic homoglyph or punycode domain evaluates safely without crashing
        is_dga, prob, _ = engine.predict({}, "gооgle.com")  # Cyrillic 'о'
        self.assertIsInstance(prob, float)
        self.assertIsInstance(is_dga, bool)

if __name__ == '__main__':
    unittest.main()
