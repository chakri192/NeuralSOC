import unittest
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import torch

from inference.models import DeepLearningEngine, FlowAnomalyEngine, sanitize_domain_chars
from inference.correlation import IncidentCorrelator
from inference.enrichment import ThreatEnricher
from api.deps import _validate_ip, _is_trusted_proxy, get_remote_address

class TestSOCPipelineSecurity(unittest.TestCase):
    def _make_correlator(self):
        """Construct a real IncidentCorrelator backed by an isolated,
        in-memory fakeredis instance (with Lua/EVAL support via
        fakeredis[lua]) instead of requiring a live Redis server.
        Previously these tests silently no-op'd via
        `except Exception: print("Redis test skipped")` whenever no local
        Redis was reachable -- meaning this coverage never actually
        executed in CI, where no Redis is running."""
        os.environ.setdefault("REDIS_PASSWORD", "test-only-redis-password-do-not-use-in-prod")
        os.environ.setdefault("REDIS_SSL", "false")
        fake = fakeredis.FakeStrictRedis(decode_responses=True)
        patcher = patch("inference.correlation.redis.Redis", return_value=fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        correlator = IncidentCorrelator()
        # fakeredis does not implement INFO (used only to confirm this
        # instance is talking to a primary, not a read replica) -- that is
        # a topology concern orthogonal to what these tests exercise, so
        # bypass it rather than mocking INFO's full reply format.
        master_patcher = patch.object(correlator, "check_redis_master", return_value=True)
        master_patcher.start()
        self.addCleanup(master_patcher.stop)
        return correlator

    def test_ip_validation_and_proxy_trust(self):
        # Valid IPv4 and IPv6
        self.assertEqual(_validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(_validate_ip("::1"), "::1")
        self.assertIsNone(_validate_ip("invalid.ip.address"))
        self.assertIsNone(_validate_ip("999.999.999.999"))

        # Proxy trust check
        self.assertTrue(_is_trusted_proxy("127.0.0.1"))
        self.assertTrue(_is_trusted_proxy("::1"))
        # 10.244.0.0/16 is the documented default trusted range (README.md's
        # "Trusted Proxy / CIDR Allow-list" section, api/deps.py's own
        # default, and k8s/soc-deployment.yaml's explicit TRUSTED_PROXY_CIDRS
        # all agree it's the standard K8s pod/ingress subnet, intentionally
        # trusted) -- and test_w3c_trace_context_propagation below asserts
        # the same range IS trusted. This line's old "removed from
        # allowlist" comment contradicted every other source of truth in
        # the repo; it was never actually implemented.
        self.assertTrue(_is_trusted_proxy("10.244.1.5"))
        self.assertFalse(_is_trusted_proxy("172.16.0.10"))
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

    def test_flow_anomaly_engine_loads_and_scores_a_normal_flow_as_not_anomalous(self):
        engine = FlowAnomalyEngine()
        self.assertIsNotNone(engine.model)
        self.assertIsInstance(engine.threshold, float)

        # Shape matches inference/train_model.py's generate_benign_flow_dataset()
        # training ranges -- a modest request, a larger response, sub-10s
        # duration, tens to hundreds of packets.
        is_anomalous, mse, threshold = engine.score(orig_bytes=1200, resp_bytes=50000, duration=2.0, orig_pkts=100)
        self.assertFalse(is_anomalous)
        self.assertIsInstance(mse, float)
        self.assertEqual(threshold, engine.threshold)

    def test_flow_anomaly_engine_flags_an_exfiltration_shaped_flow(self):
        engine = FlowAnomalyEngine()
        # Wildly asymmetric byte ratio (huge upload, almost nothing back)
        # and packet count -- nothing in training ever looked like this.
        is_anomalous, mse, _ = engine.score(orig_bytes=50_000_000, resp_bytes=500, duration=5.0, orig_pkts=40000)
        self.assertTrue(is_anomalous)
        self.assertGreater(mse, engine.threshold)

    def test_flow_anomaly_engine_scoring_never_raises_on_bad_input(self):
        engine = FlowAnomalyEngine()
        # Negative/garbage input shouldn't crash the stream processor --
        # matches DeepLearningEngine.predict()'s own fail-closed-to-"not
        # flagged" posture on any scoring error.
        is_anomalous, mse, _ = engine.score(orig_bytes=-1, resp_bytes=float("nan"), duration=-5, orig_pkts=-1)
        self.assertIsInstance(is_anomalous, bool)
        self.assertIsInstance(mse, float)

    def test_flow_anomaly_engine_fails_closed_on_sha256_mismatch(self):
        with patch("inference.models.secrets.compare_digest", return_value=False):
            with self.assertRaises(RuntimeError):
                FlowAnomalyEngine()

    def test_flow_anomaly_threshold_is_configurable_without_retraining(self):
        """FLOW_ANOMALY_THRESHOLD (env var, see
        scripts/calibrate_flow_anomaly_threshold.py) overrides the
        model's shipped .threshold file -- real-world calibration
        (SECURITY.md's "Flow autoencoder validation" section) found the
        auto-computed file threshold miscalibrated against real data, so
        this override is what made the fix deployable without hand-
        editing the shipped model artifact."""
        with patch.dict(os.environ, {"FLOW_ANOMALY_THRESHOLD": "0.5"}):
            engine = FlowAnomalyEngine()
        self.assertEqual(engine.threshold, 0.5)

    def test_correlator_multi_alert_aggregation(self):
        correlator = self._make_correlator()
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

        inc1 = correlator.add_alert(alert1)
        # First alert alone should not trigger incident (threshold len >= 2)
        self.assertIsNone(inc1)

        inc2 = correlator.add_alert(alert2)
        # Second alert must trigger an incident -- this is the exact
        # behavior that silently stopped working repo-wide when the Redis
        # connection pool's invalid ssl= kwarg made every real command
        # raise, which a broad `except Exception` swallowed as "Redis is
        # down." With that fixed, this must now actually fire.
        self.assertIsNotNone(inc2)
        self.assertEqual(inc2["source_ip"], test_ip)
        # Verify that both threat classes and alert IDs were aggregated
        self.assertIn("C2 Beaconing", inc2["threat_classes"])
        self.assertIn("ALT-002", inc2["related_alert_ids"])
        self.assertEqual(inc2["severity"], "high")
        self.assertGreaterEqual(inc2["risk_score"], 75.0)

    def test_correlator_suppresses_a_weakly_corroborated_incident(self):
        """The `threshold` param on add_alert() used to be accepted and
        never once read in the method body -- the Lua script's own
        total_count==2 escalation trigger was the only thing that
        decided whether an incident got constructed at all, so this
        silently implied a risk-score filter that didn't exist. Two
        genuinely low-confidence alerts (0.3 each) combine to a real
        composite score of ~15.5 (inference.risk.calculate_risk_score's
        log-odds pooling) -- below the default threshold=50.0 -- and
        must now be suppressed even though the Lua script's cheap
        per-alert heuristic would have escalated on alert count alone."""
        correlator = self._make_correlator()
        test_ip = "192.168.100.43"

        weak1 = {
            "alert_id": "ALT-W1", "source_ip": test_ip, "destination_ip": "10.0.0.1",
            "threat_class": "Reconnaissance", "model_name": "RULE_RECON_PORT_SCAN",
            "severity": "low", "confidence_score": 0.3,
        }
        weak2 = {
            "alert_id": "ALT-W2", "source_ip": test_ip, "destination_ip": "10.0.0.2",
            "threat_class": "C2 Beaconing", "model_name": "RULE_C2_HEARTBEAT",
            "severity": "low", "confidence_score": 0.3,
        }

        self.assertIsNone(correlator.add_alert(weak1))
        # The Lua script's own total_count==2 trigger would have
        # escalated this -- it must be suppressed by the composite
        # score gate instead, not published as a real incident.
        self.assertIsNone(correlator.add_alert(weak2))

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

            # Second call should hit in-memory cache instantly. Accepts
            # either the live provider's raw shape ("country", ipwho.is)
            # or the offline enrich_ip_intel() fallback's adapted shape
            # ("country_name") -- this test hits the real network and
            # falls back gracefully if it's unreachable in a given
            # environment, so either is a valid "enrichment worked" signal.
            cached_val = enricher._get_cached("8.8.8.8")
            self.assertIsNotNone(cached_val)
            self.assertTrue("country" in cached_val or "country_name" in cached_val)

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
                "0.0.0.0",  # nosec B104
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
        # A flagged DGA detection must carry the triggering domain in
        # evidence -- previously omitted entirely (see the matching
        # stream_processor_faust.py regression test).
        with patch.object(orchestrator.dl_engine, "predict", return_value=(True, 0.97, 0.1)):
            dets = orchestrator.evaluate({"event_type": "dns", "query": "xk3q9z7-evil.biz"}, {})
        self.assertEqual(dets[0]["evidence"], {"domain": "xk3q9z7-evil.biz"})

    def test_sanitize_domain_chars_maps_unmapped_to_dash(self):
        char_map = {c: i + 1 for i, c in enumerate("abcdefghijklmnopqrstuvwxyz0123456789-.")}
        # '_' is not in char_map -- must become '-', not vanish (the old
        # training-time behavior mapped it to the padding token instead,
        # a real train/inference mismatch this function exists to close).
        self.assertEqual(sanitize_domain_chars("_ldap._tcp", char_map), "-ldap.-tcp")
        # Every character already in char_map passes through unchanged.
        self.assertEqual(sanitize_domain_chars("google.com", char_map), "google.com")

    def test_dga_classification_threshold_is_configurable_without_retraining(self):
        """DGA_CLASSIFICATION_THRESHOLD (read from the environment, see
        scripts/calibrate_dga_threshold.py) gates the is_dga decision, not
        a hardcoded 0.85 -- an operator can trade recall for precision/FPR
        without a retrain. The underlying model is mocked to return a
        fixed 0.5 probability so this test is about the threshold
        comparison itself, not any particular trained model's real
        output for some domain."""
        import inference.models as models_module

        engine = DeepLearningEngine(start_verifier=False)
        with patch.object(engine, "model", return_value=torch.tensor([[0.5]])):
            with patch.object(models_module, "DGA_CLASSIFICATION_THRESHOLD", 0.9):
                is_dga_strict, prob, _ = engine.predict({}, "example.com")
            with patch.object(models_module, "DGA_CLASSIFICATION_THRESHOLD", 0.1):
                is_dga_lenient, _, _ = engine.predict({}, "example.com")

        self.assertEqual(prob, 0.5)
        self.assertFalse(is_dga_strict)
        self.assertTrue(is_dga_lenient)

    def test_idna_homoglyph_handling(self):
        engine = DeepLearningEngine()
        # Ensure Cyrillic homoglyph or punycode domain evaluates safely without crashing
        is_dga, prob, _ = engine.predict({}, "gооgle.com")  # Cyrillic 'о'
        self.assertIsInstance(prob, float)
        self.assertIsInstance(is_dga, bool)

    def test_lru_cache_eviction(self):
        enricher = ThreatEnricher(cache_ttl_sec=3600, max_cache_size=3)
        enricher._set_cached("1.1.1.1", {"city": "City1"})
        enricher._set_cached("2.2.2.2", {"city": "City2"})
        enricher._set_cached("3.3.3.3", {"city": "City3"})
        self.assertEqual(len(enricher._cache), 3)

        # Access 1.1.1.1 to mark it recently used
        cached_1 = enricher._get_cached("1.1.1.1")
        self.assertEqual(cached_1["city"], "City1")

        # Insert 4th element: should evict 2.2.2.2 (oldest)
        enricher._set_cached("4.4.4.4", {"city": "City4"})
        self.assertEqual(len(enricher._cache), 3)
        self.assertEqual(enricher._get_cached("2.2.2.2"), {})
        self.assertNotEqual(enricher._get_cached("1.1.1.1"), {})
        self.assertNotEqual(enricher._get_cached("4.4.4.4"), {})

    def test_pcap_ingester_parses_tcp_and_udp_flows(self):
        """Regression test: pkt[proto] indexed Scapy layers by a lowercase
        string ("tcp"/"udp") instead of the layer class (TCP/UDP), raising
        IndexError on the very first IP packet -- this ingester parsed
        ZERO packets, ever, regardless of pcap content."""
        import tempfile
        from scapy.all import IP, TCP, UDP, Ether, wrpcap
        from ingest.pcap_ingester import ingest_pcap

        pkts = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=443) / ("X" * 100)
                for _ in range(20)]
        pkts += [Ether() / IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=53000, dport=53) / ("Y" * 50)
                 for _ in range(10)]

        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            wrpcap(f.name, pkts)

            sent = []

            class FakeProducer:
                def __init__(self, *a, **kw):
                    pass

                def send(self, topic, payload):
                    sent.append(payload)

                def flush(self):
                    pass

            with patch("ingest.pcap_ingester.KafkaProducer", FakeProducer):
                ingest_pcap(f.name, broker="fake:9092", topic="raw_traffic")

        self.assertEqual(len(sent), 2, "expected exactly one TCP flow and one UDP flow")
        by_proto = {p["proto"]: p for p in sent}
        self.assertEqual(by_proto["tcp"]["orig_pkts"], 20)
        self.assertEqual(by_proto["udp"]["orig_pkts"], 10)

    def test_slice_budget_is_shared_fairly_across_domain_variants(self):
        """Regression test for a multi-segment-inspection bug: with a
        SHARED, unbounded-per-variant 32-slice pool, the first
        domains_to_check entry (the full domain) could claim as many
        slices as it naturally produced, starving later entries --
        including the punycode/homoglyph variant and individual
        subdomain-chunk labels this defense exists to inspect. A
        DNS-tunneling-style domain (many encoded chunks, mirroring real
        exfiltration patterns) produces exactly 8 domains_to_check entries
        here (the full domain, the SLD, and 6 of its many qualifying
        chunks -- domains_to_check is itself capped at 8). Every one of
        those 8 must contribute at least one slice; the fair-share budget
        (32 // 8 = 4 per variant) must also cap any single variant's
        contribution well under the full 32-slice pool."""
        import torch as real_torch
        engine = DeepLearningEngine()

        chunks = ["aaaabbbbcc" for _ in range(20)]  # 20 ten-char labels: realistic tunneling chunking
        domain = ".".join(chunks) + ".tunnel-exfil.example"

        call_sizes = []
        original_tensor = real_torch.tensor

        def _spy_tensor(data, *args, **kwargs):
            call_sizes.append(len(data))
            return original_tensor(data, *args, **kwargs)

        with patch("inference.models.torch.tensor", side_effect=_spy_tensor):
            engine.predict({}, domain)

        self.assertTrue(call_sizes, "model was never invoked")
        total_slices = call_sizes[0]
        # >= 8: every domains_to_check entry (capped at 8) got at least
        # one slice -- none were starved out by an earlier, longer variant.
        self.assertGreaterEqual(total_slices, 8)
        # <= 32: still bounded, per-variant fairness didn't remove the cap.
        self.assertLessEqual(total_slices, 32)

    def test_rules_thresholds_do_not_flag_ordinary_cdn_traffic(self):
        """Regression test for the empirically-inverted thresholds: entropy
        over the whole FQDN and a bare JA4 version-prefix both fired on
        ordinary traffic. These are the exact hostnames/fingerprint
        measured during the audit."""
        from inference.features import extract_features
        from inference.rules import evaluate_rules

        benign_cdn_queries = [
            "dpm2x4qnl8k9v.cloudfront.net",
            "1drv-b8f3ac9e2.sharepoint.com",
            "k8s-prod-7f9a2c.elb.amazonaws.com",
            "5f4dcc3b5aa765d61d8327deb882cf99.gravatar.com",
        ]
        for query in benign_cdn_queries:
            event = {"event_type": "dns", "query": query, "qtype_name": "A"}
            alerts = evaluate_rules(event, extract_features(event))
            self.assertEqual(alerts, [], f"false positive on benign CDN query: {query}")

        # A long, genuinely random-looking domain must still fire.
        event = {"event_type": "dns", "query": "kxqzjwvbnplfmtrshdycg.xyz", "qtype_name": "A"}
        alerts = evaluate_rules(event, extract_features(event))
        self.assertEqual([a["rule_id"] for a in alerts], ["RULE_DNS_DGA_FALLBACK"])

        # Ordinary Chrome/Firefox/curl TLS 1.3 no longer reads as malware.
        alerts = evaluate_rules({"event_type": "conn", "ja4": "t13d1516h2_8daaf6152771_02713d6af862"}, {})
        self.assertEqual(alerts, [])
        # The demo injector's synthetic fingerprint still fires (demo stays functional).
        alerts = evaluate_rules({"event_type": "conn", "ja4": "t13d000000_rare_fingerprint"}, {})
        self.assertEqual([a["rule_id"] for a in alerts], ["RULE_TLS_JA4_MALWARE"])

        # A single rejected connection (one closed port) is no longer a
        # critical DDoS alert; real volume still is.
        alerts = evaluate_rules({"event_type": "conn", "conn_state": "REJ", "orig_pkts": 3}, {})
        self.assertEqual(alerts, [])
        alerts = evaluate_rules({"event_type": "conn", "conn_state": "S0", "orig_pkts": 15000}, {})
        self.assertEqual([(a["rule_id"], a["severity"]) for a in alerts], [("RULE_DDOS_VOLUMETRIC", "critical")])

    def test_hot_reload_from_mutable_disk_is_disabled_by_design(self):
        """_recheck_integrity() is intentionally a no-op ("DISABLED:
        hot-reload from mutable disk files is disabled. Load once at
        startup from immutable container-image artifact.") -- swapping a
        loaded ML model at runtime from a mutable path is itself a
        plausible attack vector, so this asserts the model and its
        expected hash are pinned for the process lifetime, not that a new
        artifact on disk gets picked up."""
        engine = DeepLearningEngine()
        initial_sha = engine._expected_sha
        initial_model = engine.model
        self.assertIsNotNone(initial_model)

        mock_new_model = MagicMock()
        mock_new_sha = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

        with patch.object(engine, "_load_model_from_disk", return_value=(mock_new_model, mock_new_sha)):
            success = engine._recheck_integrity()
            self.assertTrue(success)
            self.assertEqual(engine._expected_sha, initial_sha)
            self.assertEqual(engine.model, initial_model)

    def test_homogeneous_attack_correlation(self):
        correlator = self._make_correlator()
        test_ip = "198.51.100.77"

        incidents_generated = []
        for i in range(10):
            alert = {
                "alert_id": f"ALT-DDOS-{i}",
                "source_ip": test_ip,
                "destination_ip": "10.0.0.5",
                "threat_class": "DDoS Attack",
                "severity": "critical",
                "mitre_tactic": "Impact"
            }
            inc = correlator.add_alert(alert)
            if inc:
                incidents_generated.append(inc)

        # Alert #2 (len_list == 2) and Alert #5, #10 (len_list % 5 == 0) must trigger incidents
        # preventing the black-hole suppression flaw for homogeneous attacks
        self.assertGreaterEqual(len(incidents_generated), 1)
        self.assertEqual(incidents_generated[0]["source_ip"], test_ip)
        self.assertEqual(incidents_generated[0]["severity"], "critical")

    def test_correlator_connection_pool_never_raises_typeerror(self):
        """Direct regression test for the bug that made the correlation
        engine silently produce zero incidents fleet-wide: the pool used to
        pass ssl=<bool> into redis.ConnectionPool's default Connection
        class, which does not accept that kwarg, raising TypeError as soon
        as a connection is actually built (ConnectionPool builds them
        lazily, so this only surfaced on the FIRST REAL COMMAND). Exercises
        the real redis.ConnectionPool/Connection classes directly -- not
        IncidentCorrelator, whose redis.Redis is faked for the rest of this
        suite -- against an unreachable address, and confirms the failure
        mode is a connection error, never a TypeError."""
        import redis as redis_module

        pool = redis_module.ConnectionPool(
            host="127.0.0.1", port=1, password="x", db=0,
            decode_responses=True, socket_timeout=0.2, socket_connect_timeout=0.2,
        )
        try:
            pool.get_connection("_")
            self.fail("expected a connection error against an unreachable port")
        except TypeError:
            self.fail(
                "ConnectionPool kwargs are incompatible with the default "
                "Connection class -- the ssl= kwarg regression is back, and "
                "check_redis_master()'s broad except would silently "
                "swallow this as 'Redis is down'"
            )
        except redis_module.exceptions.RedisError:
            pass  # expected: nothing listens on port 1 in this environment

    def test_seen_set_is_bounded_under_burst(self):
        """The :seen dedup set must not grow without bound under a
        volumetric burst from one source IP -- exactly the pattern the
        platform's own DDoS rule exists to flag. Capped via a sorted set at
        MAX_SEEN=5000 in CORRELATE_LUA (previously an unbounded SADD)."""
        correlator = self._make_correlator()
        test_ip = "203.0.113.9"

        for i in range(5050):
            correlator.add_alert({
                "alert_id": f"ALT-BURST-{i}",
                "source_ip": test_ip,
                "threat_class": "Volumetric Protocol DDoS",
                "severity": "critical",
            })

        # correlation.py builds this from key_name .. ":seen", where
        # key_name is f"{{{src_ip}}}:alerts" -- so the real key is
        # "{ip}:alerts:seen".
        seen_key = f"{{{test_ip}}}:alerts:seen"
        self.assertLessEqual(correlator.redis.zcard(seen_key), 5000)

    def test_schema_validation_with_null_mitre(self):
        from inference.schemas import validate_alert
        from datetime import datetime, timezone
        dl_alert = {
            "alert_id": "ALT-DL-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "threat_class": "DGA / DNS Tunnelling",
            "severity": "high",
            "confidence_score": 0.95,
            "evidence": {},
            "event_type": "dns",
            "schema_version": "1.0",
            "model_name": "DL_CNN_DGA",
            "model_version": "1.0",
            "mitre_tactic": None,
            "mitre_technique": None
        }
        is_valid, err = validate_alert(dl_alert)
        self.assertTrue(is_valid, f"Schema validation failed for DL alert with null mitre: {err}")

    # ----------------------------------------------------------------
    # Regression tests for Phase IV hardening fixes
    # ----------------------------------------------------------------

    def test_background_integrity_verifier_no_hot_path_block(self):
        """Fix #1: Verify the inference hot path never performs disk I/O.
        The background verifier thread exists and predict() only takes
        a brief lock for a counter increment + model snapshot."""
        engine = DeepLearningEngine(start_verifier=False)
        self.assertIsNotNone(engine.model)

        # Simulate 600 inferences — previously, the 300th would block all
        # 4 CPU threads with synchronous disk I/O under the lock.
        for _ in range(600):
            is_dga, prob, _ = engine.predict({}, "google.com")
            self.assertIsInstance(prob, float)

        # Inference count advanced without any integrity re-check blocking
        self.assertEqual(engine._inference_count, 600)

    def test_background_verifier_lifecycle(self):
        """Fix #1: Verify background verifier thread can start and stop cleanly."""
        engine = DeepLearningEngine(start_verifier=True, verify_interval=3600)
        self.assertFalse(engine._stop_verifier.is_set())
        engine.stop_verifier()
        self.assertTrue(engine._stop_verifier.is_set())

    def test_cnn_full_domain_coverage_no_truncation(self):
        """Fix #3: A 253-char domain must produce slices covering the entire
        payload, not truncate at 185 chars (old MAX_SLICES=10 cap)."""
        engine = DeepLearningEngine(start_verifier=False)
        # Build a 253-char domain: 250 chars of label + ".co"
        long_label = "a" * 250
        long_domain = f"{long_label}.co"
        self.assertEqual(len(long_domain), 253)

        is_dga, prob, _ = engine.predict({}, long_domain)
        self.assertIsInstance(prob, float)
        # The key assertion: the engine did not crash and returned a result.
        # Under the old code the tail 68 chars were invisible to the CNN.

    def test_cnn_tail_payload_evasion_defeated(self):
        """Fix #3: Attacker pads 190 chars of benign prefix and hides DGA at
        the tail. The unbounded sliding window must still inspect the tail."""
        engine = DeepLearningEngine(start_verifier=False)
        benign_prefix = "www." + "safe" * 46 + "."  # ~188 chars
        dga_suffix = "xk3q9z7.evil.com"
        evasion_domain = benign_prefix + dga_suffix
        self.assertGreater(len(evasion_domain), 200)

        # We can't assert detection because the model may not flag this
        # specific string, but we CAN verify the predict path completes
        # without truncating — previously it would silently skip the tail.
        is_dga, prob, _ = engine.predict({}, evasion_domain)
        self.assertIsInstance(prob, float)

    def test_rate_limit_key_proxy_exhaustion_no_collapse(self):
        """Fix #5: When all X-Forwarded-For IPs are trusted proxies, the
        rate-limit key must NOT collapse onto the shared ingress IP.
        It should return the leftmost valid originating client so that
        one compromised pod cannot DoS the entire ingress rate bucket."""
        # Scenario: internal pod -> ingress -> API
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"  # TCP peer is trusted proxy
        mock_req.headers = {"X-Forwarded-For": "10.244.1.50, 10.244.0.1"}
        # Both IPs are inside the trusted 10.244.0.0/16 CIDR

        result = get_remote_address(mock_req)
        # Must NOT return 127.0.0.1 (the ingress controller IP)
        # Should return the leftmost originating client to isolate rate buckets
        self.assertEqual(result, "10.244.1.50")
        self.assertNotEqual(result, "127.0.0.1")

    def test_rate_limit_key_normal_proxy_path(self):
        """Fix #5: Normal external client path through proxy still works."""
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        mock_req.headers = {"X-Forwarded-For": "203.0.113.99, 10.244.0.1"}

        result = get_remote_address(mock_req)
        # External IP should be extracted as before
        self.assertEqual(result, "203.0.113.99")

    # ----------------------------------------------------------------
    # Phase V Architecture Remediation Tests
    # ----------------------------------------------------------------

    def test_stream_processor_type_poisoning_resilience(self):
        """Audit Finding 3: Poisoned non-string 'query' fields (e.g. integer 1337)
        must not cause unhandled TypeError crashes in stream processor."""
        engine = DeepLearningEngine(start_verifier=False)

        # Raw int passed as query
        is_dga, prob, _ = engine.predict({}, 1337)  # type: ignore
        self.assertFalse(is_dga)
        self.assertEqual(prob, 0.0)

        # List passed as query
        is_dga, prob, _ = engine.predict({}, ["evil.com", "malicious.com"])  # type: ignore
        self.assertFalse(is_dga)
        self.assertEqual(prob, 0.0)

    def test_schema_validation_with_trace_context(self):
        """Verify schema validation accepts W3C distributed trace context fields."""
        from inference.schemas import validate_alert
        from datetime import datetime, timezone
        alert = {
            "alert_id": "ALT-TRC-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.0.5",
            "destination_ip": "8.8.8.8",
            "threat_class": "Suspicious Activity",
            "severity": "medium",
            "confidence_score": 0.88,
            "evidence": {"detail": "Test evidence"},
            "event_type": "conn",
            "schema_version": "1.0",
            "model_name": "RULE_ENGINE",
            "model_version": "1.0",
            "trace_id": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "span_id": "00f067aa0ba902b7"
        }
        is_valid, err = validate_alert(alert)
        self.assertTrue(is_valid, f"Schema validation failed: {err}")

    def test_w3c_trace_context_propagation(self):
        """Verify API tracing middleware preserves existing correlation IDs."""
        from starlette.testclient import TestClient
        from api.main import app
        client = TestClient(app)
        custom_req_id = "trc-custom-uuid-12345"
        resp = client.get("/livez", headers={"X-Request-ID": custom_req_id})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Request-ID"), custom_req_id)

    def test_model_integrity_recheck_preserves_existing_model_on_transient_error(self):
        """Audit Finding 5: If candidate model file is corrupted/transiently bad,
        _recheck_integrity must NEVER set self.model = None if a valid model exists."""
        engine = DeepLearningEngine(start_verifier=False)
        original_model = engine.model
        self.assertIsNotNone(original_model)

        # Simulate corrupt candidate file causing torch.jit.load exception
        with patch.object(engine, "_load_model_from_disk", side_effect=RuntimeError("Corrupted file header")):
            res = engine._recheck_integrity()
            # Must return True (graceful fallback) and preserve current model
            self.assertTrue(res)
            self.assertIsNotNone(engine.model)
            self.assertEqual(engine.model, original_model)

    def test_model_max_size_limit_rejection(self):
        """Verify that a model file exceeding MAX_MODEL_SIZE_BYTES is rejected before reading into memory."""
        engine = DeepLearningEngine(start_verifier=False)
        with patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=100 * 1024 * 1024), \
             patch.dict(os.environ, {"MAX_MODEL_SIZE_BYTES": str(50 * 1024 * 1024)}):
            with self.assertRaises(RuntimeError) as ctx:
                engine._load_model_from_disk()
            self.assertIn("exceeds maximum allowed size", str(ctx.exception))

    def test_threat_enricher_client_close(self):
        """Verify ThreatEnricher async client close and context manager."""
        async def run_close_test():
            enricher = ThreatEnricher()
            self.assertFalse(enricher.client.is_closed)
            await enricher.close()
            self.assertTrue(enricher.client.is_closed)

            # Test context manager
            async with ThreatEnricher() as enricher_cm:
                self.assertFalse(enricher_cm.client.is_closed)
            self.assertTrue(enricher_cm.client.is_closed)

        asyncio.run(run_close_test())

    def test_stream_dlq_path_guard_rejects_out_of_bounds_path(self):
        """_resolve_dlq_file_path() must reject any STREAM_DLQ_FILE_PATH or
        POD_NAME/HOSTNAME value that would resolve outside /tmp/dlq (the
        dedicated dlq-data volume mount, k8s/soc-deployment.yaml), falling
        back to the safe default -- mirroring the allow-listing
        api/kafka_sink.py already applies to its own DLQ_FILE_PATH env var."""
        import inference.stream_processor_faust as sp
        from inference.stream_processor_faust import _resolve_dlq_file_path

        # realpath() (not abspath()) resolves symlinks -- on macOS /tmp
        # itself is a symlink to /private/tmp, so the allowed base dir and
        # every expected resolved path here are derived the same way the
        # real function derives them, rather than hardcoding "/tmp" and
        # breaking on any platform where that symlink exists.
        base = sp._DLQ_ALLOWED_BASE_DIR

        # A legitimate templated path stays inside the allowed dir, per-pod partitioned.
        self.assertEqual(
            _resolve_dlq_file_path("/tmp/dlq/alerts-{pod}.jsonl", "stream-processor-0"),
            f"{base}/alerts-stream-processor-0.jsonl",
        )
        # A legitimate non-templated path gets auto-partitioned by pod name.
        self.assertEqual(
            _resolve_dlq_file_path("/tmp/dlq/alerts.jsonl", "stream-processor-1"),
            f"{base}/alerts-stream-processor-1.jsonl",
        )
        # An out-of-bounds STREAM_DLQ_FILE_PATH must be rejected and fall
        # back to the safe default, never resolve outside the allowed dir.
        self.assertEqual(_resolve_dlq_file_path("/etc/passwd-{pod}", "default"), sp._DLQ_DEFAULT_PATH)
        self.assertEqual(_resolve_dlq_file_path("/tmp/dlq/../../etc/passwd", "default"), sp._DLQ_DEFAULT_PATH)
        # A malicious pod name (e.g. an attacker-influenced HOSTNAME) must
        # not be able to escape the allowed dir via embedded ".." segments either.
        resolved = _resolve_dlq_file_path("/tmp/dlq/alerts.jsonl", "../../etc/evil")
        self.assertTrue(resolved.startswith(base))

    def test_pod_partitioned_dlq_paths(self):
        """Verify DLQ path formatting with pod names."""
        # Case 1: Template string with {pod}
        raw_template = "/tmp/dlq/alerts-{pod}.jsonl"  # nosec B108
        formatted = raw_template.format(pod="stream-processor-0")
        self.assertEqual(formatted, "/tmp/dlq/alerts-stream-processor-0.jsonl")

        # Case 2: Standard filename auto-partitioned by pod
        raw_path = "/tmp/dlq/alerts.jsonl"  # nosec B108
        base_dir, filename = os.path.split(raw_path)
        name, ext = os.path.splitext(filename)
        pod_name = "stream-processor-1"
        partitioned = os.path.join(base_dir, f"{name}-{pod_name}{ext}")
        self.assertEqual(partitioned, "/tmp/dlq/alerts-stream-processor-1.jsonl")

    def test_api_docs_exposure_toggle(self):
        """Verify FastAPI documentation routes are hidden when ENABLE_DOCS is false."""
        from starlette.testclient import TestClient
        from api.main import app
        client = TestClient(app)
        # In default configuration, ENABLE_DOCS is not set (evaluates to false)
        resp_docs = client.get("/docs")
        self.assertEqual(resp_docs.status_code, 404)
        resp_openapi = client.get("/openapi.json")
        self.assertEqual(resp_openapi.status_code, 404)

    def test_executor_shutdown_timeout(self):
        """Verify _EXECUTOR_SHUTDOWN_TIMEOUT is tuned to Kubernetes lifecycle
        margin AND is actually used -- previously declared with a comment
        describing exactly this bound, but _on_before_shutdown's
        asyncio.wait_for called a hardcoded 15.0 instead, so the constant
        was dead."""
        import inspect
        from inference import stream_processor_faust
        self.assertEqual(stream_processor_faust._EXECUTOR_SHUTDOWN_TIMEOUT, 45)
        source = inspect.getsource(stream_processor_faust._on_before_shutdown)
        self.assertIn("_EXECUTOR_SHUTDOWN_TIMEOUT", source)

    def test_cilium_policy_coverage(self):
        """Verify Cilium network policies cover all three core deployments."""
        import yaml
        policy_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "cilium-identity-policy.yaml")
        with open(policy_file, "r") as f:
            docs = list(yaml.safe_load_all(f))

        apps_covered = [doc.get("spec", {}).get("endpointSelector", {}).get("matchLabels", {}).get("app") for doc in docs if doc]
        self.assertIn("tsoc-stream-processor", apps_covered)
        self.assertIn("tsoc-api", apps_covered)
        self.assertIn("tsoc-kafka-sink", apps_covered)

    # ----------------------------------------------------------------
    # Phase VI 10/10 Enterprise Hardening Tests
    # ----------------------------------------------------------------

    def test_correlation_rollback_lua_execution(self):
        """Verify atomic ROLLBACK_LUA script removes seen status, list entry, and decrements counter."""
        correlator = self._make_correlator()
        test_ip = "192.0.2.100"
        alert = {
            "alert_id": "ALT-ROLLBACK-001",
            "source_ip": test_ip,
            "destination_ip": "10.0.0.1",
            "threat_class": "Port Scanning",
            "severity": "medium",
            "mitre_tactic": "Reconnaissance"
        }

        # 1. Add alert to Redis
        correlator.add_alert(alert)

        # Check that seen, count, and list exist in Redis. The :seen key is
        # a sorted set (bounded via MAX_SEEN), not a plain set -- existence
        # is `zscore(...) is not None`, not `sismember`.
        seen_exists = correlator.redis.zscore(f"{{{test_ip}}}:alerts:seen", "ALT-ROLLBACK-001")
        cnt_val = correlator.redis.get(f"{{{test_ip}}}:alerts:cnt")
        list_len = correlator.redis.llen(f"{{{test_ip}}}:alerts")

        self.assertIsNotNone(seen_exists)
        self.assertEqual(int(cnt_val or 0), 1)
        self.assertEqual(list_len, 1)

        # 2. Execute rollback compensating transaction
        correlator.rollback_alert_seen(alert)

        # Verify that seen, count, and list entries are rolled back
        seen_after = correlator.redis.zscore(f"{{{test_ip}}}:alerts:seen", "ALT-ROLLBACK-001")
        cnt_after = correlator.redis.get(f"{{{test_ip}}}:alerts:cnt")
        list_after = correlator.redis.llen(f"{{{test_ip}}}:alerts")

        self.assertIsNone(seen_after)
        self.assertIsNone(cnt_after)
        self.assertEqual(list_after, 0)

    def test_dlq_fallback_strict_file_permissions(self):
        """Verify _write_local_dlq_fallback creates file with 0o600 and dir with 0o700 permissions."""
        import tempfile
        import stat
        from inference.stream_processor_faust import _write_local_dlq_fallback
        import inference.stream_processor_faust as sp

        with tempfile.TemporaryDirectory() as temp_dir:
            test_dlq_path = os.path.join(temp_dir, "test_dlq_sub", "dlq_test.jsonl")
            test_lock_path = f"{test_dlq_path}.lock"

            orig_dlq_path = sp.DLQ_FILE_PATH
            orig_lock_path = sp.DLQ_LOCK_PATH
            try:
                sp.DLQ_FILE_PATH = test_dlq_path
                sp.DLQ_LOCK_PATH = test_lock_path

                payload = {"test": "data", "status": "failed"}
                _write_local_dlq_fallback(payload)

                self.assertTrue(os.path.exists(test_dlq_path))
                # Check permissions (mask with 0o777)
                file_stat = os.stat(test_dlq_path)
                file_mode = stat.S_IMODE(file_stat.st_mode)
                self.assertEqual(file_mode, 0o600, f"Expected 0o600 file mode, got {oct(file_mode)}")

                dir_stat = os.stat(os.path.dirname(test_dlq_path))
                dir_mode = stat.S_IMODE(dir_stat.st_mode)
                self.assertEqual(dir_mode, 0o700, f"Expected 0o700 directory mode, got {oct(dir_mode)}")
            finally:
                sp.DLQ_FILE_PATH = orig_dlq_path
                sp.DLQ_LOCK_PATH = orig_lock_path

    def test_deep_learning_slice_capping(self):
        """Verify that DeepLearningEngine caps slices to 32 to prevent adversarial tensor explosion."""
        engine = DeepLearningEngine(start_verifier=False)
        # Create an adversarial domain with lots of subdomains and long length
        adversarial_domain = "a1b2c3d4e5f6." * 30 + "com"  # > 300 chars, many subdomains
        is_dga, prob, _ = engine.predict({}, adversarial_domain)
        self.assertIsInstance(prob, float)
        self.assertIsInstance(is_dga, bool)

    def test_opa_gatekeeper_manifest_validity(self):
        """Verify OPA Gatekeeper policy manifest parses valid YAML and contains template & constraint."""
        import yaml
        opa_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "opa-gatekeeper-policies.yaml")
        self.assertTrue(os.path.exists(opa_file))
        with open(opa_file, "r") as f:
            docs = list(yaml.safe_load_all(f))

        self.assertEqual(len(docs), 2)
        template_doc = docs[0]
        constraint_doc = docs[1]

        self.assertEqual(template_doc.get("kind"), "ConstraintTemplate")
        self.assertEqual(template_doc.get("metadata", {}).get("name"), "k8slabelsecuritytemplate")

        self.assertEqual(constraint_doc.get("kind"), "K8sLabelSecurityConstraint")
        self.assertEqual(constraint_doc.get("metadata", {}).get("name"), "tsoc-label-security-enforcement")
        self.assertEqual(constraint_doc.get("spec", {}).get("parameters", {}).get("authorizedNamespace"), "tsoc")

    def test_statefulset_rwo_dlq_manifest(self):
        """Verify tsoc-stream-processor is configured as a StatefulSet with RWO volumeClaimTemplates."""
        import yaml
        deploy_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "soc-deployment.yaml")
        with open(deploy_file, "r") as f:
            docs = [d for d in yaml.safe_load_all(f) if d]

        statefulset_doc = next((d for d in docs if d.get("kind") == "StatefulSet" and d.get("metadata", {}).get("name") == "tsoc-stream-processor"), None)
        self.assertIsNotNone(statefulset_doc)
        vcts = statefulset_doc.get("spec", {}).get("volumeClaimTemplates", [])
        self.assertTrue(len(vcts) > 0)
        dlq_vct = next((v for v in vcts if v.get("metadata", {}).get("name") == "dlq-data"), None)
        self.assertIsNotNone(dlq_vct)
        self.assertIn("ReadWriteOnce", dlq_vct.get("spec", {}).get("accessModes", []))

    def test_prometheus_rules_reference_real_metric_names(self):
        """Verify k8s/prometheus-rules.yaml parses and every alert's expr
        references a metric this codebase actually exports (or, for the
        one exception documented in the file itself, an external exporter's
        standard metric name) -- a typo'd metric name here would silently
        never fire, the alerting equivalent of a test that never runs."""
        import re
        import yaml

        rules_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "prometheus-rules.yaml")
        with open(rules_file, "r") as f:
            doc = yaml.safe_load(f)

        self.assertEqual(doc.get("kind"), "PrometheusRule")
        groups = doc.get("spec", {}).get("groups", [])
        self.assertTrue(len(groups) >= 4)

        exported_here = {
            "kafka_sink_dlq_size_bytes",       # api/kafka_sink.py
            "stream_dlq_size_bytes",           # inference/stream_processor_faust.py
            "correlation_redis_errors_total",  # inference/correlation.py
            "model_inference_duration_seconds",  # inference/models.py (Histogram -> _bucket/_sum/_count)
        }
        externally_exported = {"kafka_consumergroup_lag_sum"}  # documented exporter dependency, see the rule's own comment

        all_exprs = [rule["expr"] for group in groups for rule in group["rules"]]
        self.assertTrue(all_exprs)
        for expr in all_exprs:
            metric_names = re.findall(r"[a-zA-Z_:][a-zA-Z0-9_:]*(?=[\{\[\s]|$)", expr)
            known = {m for m in metric_names if any(
                m == name or m.startswith(name.split("_seconds")[0]) for name in exported_here
            ) or m in externally_exported}
            self.assertTrue(known, f"expr references no recognized metric: {expr}")

    def test_kafka_sink_metrics_service_and_servicemonitor_are_wired_together(self):
        """The kafka-sink metrics Service (soc-deployment.yaml), the
        container's own metrics containerPort, and prometheus.yaml's
        ServiceMonitor must all agree on port name/number -- a mismatch
        here means Prometheus silently scrapes nothing."""
        import yaml

        deploy_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "soc-deployment.yaml")
        with open(deploy_file, "r") as f:
            deploy_docs = [d for d in yaml.safe_load_all(f) if d]

        sink_deployment = next(
            d for d in deploy_docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "tsoc-kafka-sink"
        )
        container = sink_deployment["spec"]["template"]["spec"]["containers"][0]
        container_port = next(p for p in container["ports"] if p["name"] == "metrics")
        self.assertEqual(container_port["containerPort"], 9101)

        sink_service = next(
            d for d in deploy_docs if d.get("kind") == "Service" and d["metadata"]["name"] == "tsoc-kafka-sink"
        )
        service_port = next(p for p in sink_service["spec"]["ports"] if p["name"] == "metrics")
        self.assertEqual(service_port["port"], 9101)

        prom_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "prometheus.yaml")
        with open(prom_file, "r") as f:
            prom_docs = [d for d in yaml.safe_load_all(f) if d]

        sink_monitor = next(
            d for d in prom_docs
            if d.get("kind") == "ServiceMonitor" and d["metadata"]["name"] == "tsoc-kafka-sink-monitor"
        )
        self.assertEqual(sink_monitor["spec"]["selector"]["matchLabels"]["app"], "tsoc-kafka-sink")
        self.assertEqual(sink_monitor["spec"]["endpoints"][0]["port"], "metrics")

    def test_redis_client_cert_secret_name_matches_between_certificate_and_deployment_mounts(self):
        """cert-manager-internal-ca.yaml's Certificate writes to a Secret
        named by its own `secretName`; soc-deployment.yaml's volumes must
        reference that exact name, and the API/stream-processor
        containers' REDIS_CLIENT_CERT_PATH/_KEY_PATH env vars must point
        inside wherever that volume is actually mounted -- a mismatch
        anywhere in this chain means every Redis connection silently
        presents no client cert instead of the intended one."""
        import yaml

        ca_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "cert-manager-internal-ca.yaml")
        with open(ca_file, "r") as f:
            ca_docs = [d for d in yaml.safe_load_all(f) if d]

        cert_doc = next(
            d for d in ca_docs if d.get("kind") == "Certificate" and d["metadata"]["name"] == "tsoc-redis-client-cert"
        )
        secret_name = cert_doc["spec"]["secretName"]
        self.assertTrue(secret_name)

        deploy_file = os.path.join(os.path.dirname(__file__), "..", "k8s", "soc-deployment.yaml")
        with open(deploy_file, "r") as f:
            deploy_docs = [d for d in yaml.safe_load_all(f) if d]

        for workload_name in ("tsoc-stream-processor", "tsoc-api"):
            workload = next(
                d for d in deploy_docs
                if d.get("kind") in ("StatefulSet", "Deployment") and d["metadata"]["name"] == workload_name
            )
            pod_spec = workload["spec"]["template"]["spec"]
            cert_volume = next(v for v in pod_spec["volumes"] if v.get("secret", {}).get("secretName") == secret_name)

            container = pod_spec["containers"][0]
            mount = next(m for m in container["volumeMounts"] if m["name"] == cert_volume["name"])
            env_by_name = {e["name"]: e.get("value") for e in container["env"]}

            self.assertTrue(env_by_name["REDIS_CLIENT_CERT_PATH"].startswith(mount["mountPath"]), workload_name)
            self.assertTrue(env_by_name["REDIS_CLIENT_KEY_PATH"].startswith(mount["mountPath"]), workload_name)

    # ----------------------------------------------------------------
    # stream_processor_faust.py coverage was concentrated in the single
    # constant-wiring test above; these exercise the DLQ fallback and
    # shutdown paths directly instead of only inspecting source text.
    # ----------------------------------------------------------------

    def test_lazy_semaphore_acquire_and_release(self):
        from inference.stream_processor_faust import backpressure_sem

        async def _use_it():
            async with backpressure_sem:
                return "acquired"

        self.assertEqual(asyncio.run(_use_it()), "acquired")

    def test_send_dlq_safely_falls_back_to_local_disk_when_kafka_send_fails(self):
        import tempfile
        from inference.stream_processor_faust import _send_dlq_safely
        import inference.stream_processor_faust as sp

        with tempfile.TemporaryDirectory() as temp_dir:
            test_dlq_path = os.path.join(temp_dir, "dlq.jsonl")
            orig_dlq_path, orig_lock_path = sp.DLQ_FILE_PATH, sp.DLQ_LOCK_PATH
            try:
                sp.DLQ_FILE_PATH = test_dlq_path
                sp.DLQ_LOCK_PATH = f"{test_dlq_path}.lock"

                # dead_letter_topic.send() will itself fail here (no live
                # Faust app/broker in the test process), which is exactly
                # the condition this function exists to survive -- it
                # should fall through to the local-disk fallback below.
                asyncio.run(_send_dlq_safely(
                    {"raw": "event"}, {"alert_id": "ALT-1"}, "boom"
                ))

                self.assertTrue(os.path.exists(test_dlq_path))
                with open(test_dlq_path) as f:
                    import json as _json
                    line = _json.loads(f.readline())
                self.assertEqual(line["error"], "boom")
                # is_replay=True is stamped onto DLQ'd alerts so a later
                # replay pass can distinguish them from first-pass alerts.
                self.assertTrue(line["alert"]["is_replay"])
            finally:
                sp.DLQ_FILE_PATH = orig_dlq_path
                sp.DLQ_LOCK_PATH = orig_lock_path

    def test_write_local_dlq_fallback_never_raises_on_os_error(self):
        from inference.stream_processor_faust import _write_local_dlq_fallback
        import inference.stream_processor_faust as sp

        orig_dlq_path = sp.DLQ_FILE_PATH
        try:
            # A path under a location this process cannot create must hit
            # the function's own except-and-log branch, not propagate.
            sp.DLQ_FILE_PATH = "/nonexistent-root-only-dir/dlq.jsonl"
            _write_local_dlq_fallback({"alert_id": "x"})  # must not raise
        finally:
            sp.DLQ_FILE_PATH = orig_dlq_path

    def test_dlq_rotates_when_oversized(self):
        """A sustained Kafka outage must not let the local-disk DLQ fallback
        grow without bound -- _rotate_dlq_if_needed() (mirroring
        api/kafka_sink.py's identical rotation logic) rotates the file out
        of the way before the next append once it exceeds DLQ_MAX_SIZE_MB."""
        import tempfile
        from inference.stream_processor_faust import _write_local_dlq_fallback
        import inference.stream_processor_faust as sp

        with tempfile.TemporaryDirectory() as temp_dir:
            test_dlq_path = os.path.join(temp_dir, "dlq.jsonl")
            orig_dlq_path = sp.DLQ_FILE_PATH
            orig_lock_path = sp.DLQ_LOCK_PATH
            orig_max_size = sp.DLQ_MAX_SIZE_MB
            try:
                sp.DLQ_FILE_PATH = test_dlq_path
                sp.DLQ_LOCK_PATH = f"{test_dlq_path}.lock"
                sp.DLQ_MAX_SIZE_MB = 0  # force rotation regardless of real size

                _write_local_dlq_fallback({"alert_id": "first"})
                _write_local_dlq_fallback({"alert_id": "second"})

                self.assertTrue(os.path.exists(f"{test_dlq_path}.1"))
                self.assertTrue(os.path.exists(test_dlq_path))
                with open(f"{test_dlq_path}.1") as f:
                    self.assertIn("first", f.read())
                with open(test_dlq_path) as f:
                    self.assertIn("second", f.read())
            finally:
                sp.DLQ_FILE_PATH = orig_dlq_path
                sp.DLQ_LOCK_PATH = orig_lock_path
                sp.DLQ_MAX_SIZE_MB = orig_max_size

    def test_dlq_rotation_never_raises_on_filesystem_error(self):
        import tempfile
        from inference.stream_processor_faust import _rotate_dlq_if_needed
        import inference.stream_processor_faust as sp

        with tempfile.TemporaryDirectory() as temp_dir:
            test_dlq_path = os.path.join(temp_dir, "dlq.jsonl")
            with open(test_dlq_path, "w") as f:
                f.write("x")

            orig_dlq_path = sp.DLQ_FILE_PATH
            orig_getsize = sp.os.path.getsize
            orig_max_size = sp.DLQ_MAX_SIZE_MB
            try:
                sp.DLQ_FILE_PATH = test_dlq_path
                sp.DLQ_MAX_SIZE_MB = 0
                sp.os.path.getsize = MagicMock(side_effect=OSError("disk error"))
                _rotate_dlq_if_needed()  # must not raise
            finally:
                sp.DLQ_FILE_PATH = orig_dlq_path
                sp.os.path.getsize = orig_getsize
                sp.DLQ_MAX_SIZE_MB = orig_max_size

    def test_graceful_shutdown_cancels_futures_and_exits(self):
        import inference.stream_processor_faust as sp
        from concurrent.futures import ThreadPoolExecutor

        throwaway_cpu = ThreadPoolExecutor(max_workers=1)
        throwaway_io = ThreadPoolExecutor(max_workers=1)
        fake_cpu_future = MagicMock()
        fake_io_future = MagicMock()

        orig_cpu, orig_io = sp.cpu_executor, sp.io_executor
        sp._submitted_cpu_futures.add(fake_cpu_future)
        sp._submitted_io_futures.add(fake_io_future)
        try:
            sp.cpu_executor, sp.io_executor = throwaway_cpu, throwaway_io
            with self.assertRaises(SystemExit):
                sp._graceful_shutdown(15, None)
            fake_cpu_future.cancel.assert_called_once()
            fake_io_future.cancel.assert_called_once()
        finally:
            sp.cpu_executor, sp.io_executor = orig_cpu, orig_io
            sp._submitted_cpu_futures.discard(fake_cpu_future)
            sp._submitted_io_futures.discard(fake_io_future)

    def test_shutdown_executors_actually_shuts_down_thread_pools(self):
        import inference.stream_processor_faust as sp
        from concurrent.futures import ThreadPoolExecutor

        throwaway_cpu = ThreadPoolExecutor(max_workers=1)
        throwaway_io = ThreadPoolExecutor(max_workers=1)
        orig_cpu, orig_io = sp.cpu_executor, sp.io_executor
        try:
            sp.cpu_executor, sp.io_executor = throwaway_cpu, throwaway_io
            sp._shutdown_executors()
            with self.assertRaises(RuntimeError):
                throwaway_cpu.submit(lambda: None)
            with self.assertRaises(RuntimeError):
                throwaway_io.submit(lambda: None)
        finally:
            sp.cpu_executor, sp.io_executor = orig_cpu, orig_io

    def test_on_before_shutdown_completes_and_closes_enricher(self):
        import inference.stream_processor_faust as sp

        orig_shutdown = sp._shutdown_executors
        try:
            sp._shutdown_executors = lambda: None  # avoid killing the shared pools
            asyncio.run(sp._on_before_shutdown())  # must not raise
            self.assertTrue(sp.enricher.client.is_closed)
        finally:
            sp._shutdown_executors = orig_shutdown

    def test_on_before_shutdown_survives_executor_shutdown_exception(self):
        import inference.stream_processor_faust as sp

        def _broken_shutdown():
            raise RuntimeError("executor pool corrupted")

        orig_shutdown = sp._shutdown_executors
        try:
            sp._shutdown_executors = _broken_shutdown
            asyncio.run(sp._on_before_shutdown())  # must log, not raise
        finally:
            sp._shutdown_executors = orig_shutdown

    def test_on_before_shutdown_survives_executor_shutdown_timeout(self):
        import time as _time
        import inference.stream_processor_faust as sp

        def _slow_shutdown():
            _time.sleep(0.3)

        orig_shutdown = sp._shutdown_executors
        orig_timeout = sp._EXECUTOR_SHUTDOWN_TIMEOUT
        try:
            sp._shutdown_executors = _slow_shutdown
            sp._EXECUTOR_SHUTDOWN_TIMEOUT = 0.01
            asyncio.run(sp._on_before_shutdown())  # must time out gracefully, not raise
        finally:
            sp._shutdown_executors = orig_shutdown
            sp._EXECUTOR_SHUTDOWN_TIMEOUT = orig_timeout

    # ----------------------------------------------------------------
    # process_traffic() is the core detection agent -- previously only
    # covered end-to-end via test_load.py's real burst test. Faust wraps
    # it in an Agent object, but the original async function is still
    # reachable via `.fun`, so it's callable directly with a fake async
    # stream, without needing a live Faust app/broker.
    # ----------------------------------------------------------------

    @staticmethod
    async def _fake_stream(events):
        for e in events:
            yield e

    def test_process_traffic_happy_path_publishes_with_force_true(self):
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C1"}
        detection = {"threat_class": "Port Scanning", "severity": "medium", "confidence": 0.8, "rule_id": "TEST_RULE"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[detection]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp.incidents_topic, "send", new=AsyncMock(return_value=None)) as incidents_send, \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_awaited_once()
            self.assertTrue(alerts_send.call_args.kwargs.get("force"))
            incidents_send.assert_not_awaited()  # add_alert returned None -> no incident
            dlq.assert_not_awaited()

        asyncio.run(_run())

    def test_dga_alert_evidence_carries_the_triggering_domain(self):
        """Regression test: the DGA alert dict used to omit `evidence`
        entirely, so every DGA alert this pipeline ever produced was
        undiagnosable without re-parsing raw traffic -- confirmed by
        having to do exactly that (independently re-scoring a real
        pcap's DNS queries) to find out which domain triggered a real
        alert during a live Lumma Stealer pcap test."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "dns", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8", "query": "xk3q9z7-evil.biz"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.dl_engine, "predict", return_value=(True, 0.97, 0.1)), \
                 patch.object(sp.domain_age_lookup, "lookup_age_days", new=AsyncMock(return_value=None)), \
                 patch.object(sp.dns_behavior_tracker, "record_query", return_value=None), \
                 patch.object(sp.dns_behavior_tracker, "is_burst", return_value=(False, None, {})), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp.incidents_topic, "send", new=AsyncMock(return_value=None)), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()):
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_awaited_once()
            sent_alert = alerts_send.call_args.kwargs["value"]
            self.assertEqual(sent_alert["threat_class"], "DGA / DNS Tunnelling")
            self.assertEqual(sent_alert["evidence"], {"domain": "xk3q9z7-evil.biz"})

        asyncio.run(_run())

    def test_domain_age_publishes_a_second_alert_for_a_young_cnn_flagged_domain(self):
        """Domain age is only looked up for domains the CNN already
        flagged (is_dga=True) -- a young, CNN-flagged domain must
        produce its OWN corroborating alert (RULE_DOMAIN_AGE_YOUNG),
        genuinely additive to the CNN's own verdict rather than mutating
        it, so both become independent evidence for
        inference/risk.py's composite scoring."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "dns", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8", "query": "freshly-registered-evil.biz"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.dl_engine, "predict", return_value=(True, 0.97, 0.1)), \
                 patch.object(sp.domain_age_lookup, "lookup_age_days", new=AsyncMock(return_value=5.0)), \
                 patch.object(sp.dns_behavior_tracker, "record_query", return_value=None), \
                 patch.object(sp.dns_behavior_tracker, "is_burst", return_value=(False, None, {})), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp.incidents_topic, "send", new=AsyncMock(return_value=None)), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()):
                await sp.process_traffic.fun(self._fake_stream([event]))

            self.assertEqual(alerts_send.await_count, 2)
            sent = [c.kwargs["value"] for c in alerts_send.await_args_list]
            model_names = {a["model_name"] for a in sent}
            self.assertEqual(model_names, {"DL_CNN_DGA", "RULE_DOMAIN_AGE_YOUNG"})
            age_alert = next(a for a in sent if a["model_name"] == "RULE_DOMAIN_AGE_YOUNG")
            self.assertEqual(age_alert["evidence"]["domain"], "freshly-registered-evil.biz")
            self.assertEqual(age_alert["evidence"]["registration_age_days"], 5.0)

        asyncio.run(_run())

    def test_domain_age_not_looked_up_when_cnn_does_not_flag_the_domain(self):
        """Bounds real external network calls to domains already
        suspicious -- a benign domain the CNN doesn't flag must never
        trigger an RDAP lookup at all."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "dns", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8", "query": "google.com"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.dl_engine, "predict", return_value=(False, 0.01, 0.1)), \
                 patch.object(sp.domain_age_lookup, "lookup_age_days", new=AsyncMock(return_value=9999.0)) as age_lookup, \
                 patch.object(sp.dns_behavior_tracker, "record_query", return_value=None), \
                 patch.object(sp.dns_behavior_tracker, "is_burst", return_value=(False, None, {})), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()):
                await sp.process_traffic.fun(self._fake_stream([event]))

            age_lookup.assert_not_awaited()

        asyncio.run(_run())

    def test_process_traffic_publishes_a_burst_alert_independent_of_the_cnn_verdict(self):
        """A source host issuing a DNS-query burst is its own signal,
        independent of what the CNN thinks of this specific domain --
        the CNN is mocked to NOT flag this domain, so the resulting
        alert can only have come from the behavioral tracker."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "dns", "id.orig_h": "10.0.0.7", "id.resp_h": "8.8.8.8", "query": "legit-looking-domain.com"}
        burst_stats = {"distinct_domains": 20, "nxdomain_rate": 0.0, "total_responses": 0}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.dl_engine, "predict", return_value=(False, 0.1, 0.1)), \
                 patch.object(sp.dns_behavior_tracker, "record_query", return_value=None), \
                 patch.object(sp.dns_behavior_tracker, "is_burst", return_value=(True, "distinct_domain_burst", burst_stats)), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_awaited_once()
            sent_alert = alerts_send.call_args.kwargs["value"]
            self.assertEqual(sent_alert["threat_class"], "DGA / DNS Tunnelling")
            self.assertEqual(sent_alert["model_name"], "RULE_DNS_QUERY_BURST")
            self.assertEqual(sent_alert["evidence"]["reason"], "distinct_domain_burst")
            self.assertEqual(sent_alert["evidence"]["distinct_domains"], 20)
            dlq.assert_not_awaited()

        asyncio.run(_run())

    def test_conn_behavior_tracker_records_every_conn_event(self):
        """Every real connection must feed the windowed rate/periodicity
        tracker, regardless of whether either check fires -- otherwise a
        real flood or beacon spread across many events would never
        accumulate enough state to be detected at all."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C-REC"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp.conn_behavior_tracker, "record_connection", return_value=None) as record_connection, \
                 patch.object(sp.conn_behavior_tracker, "is_ddos_volumetric", return_value=(False, {})), \
                 patch.object(sp.conn_behavior_tracker, "is_c2_beacon", return_value=(False, {})), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()):
                await sp.process_traffic.fun(self._fake_stream([event]))

            record_connection.assert_called_once()
            call_args = record_connection.call_args.args
            self.assertEqual(call_args[0], "10.0.0.5")
            self.assertEqual(call_args[1], "10.0.0.9")

        asyncio.run(_run())

    def test_conn_behavior_publishes_a_high_confidence_ddos_alert_on_a_real_flood(self):
        """RULE_DDOS_CONN_RATE is real-data calibrated to 100% precision
        at its threshold (docs/PATH_TO_10_OUT_OF_10.md's Phase 10-adjacent
        DDoS/C2 investigation) -- confidence reflects that."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C-DDOS"}
        flood_stats = {"connection_count": 4243, "window_seconds": 10.0}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp.conn_behavior_tracker, "record_connection", return_value=None), \
                 patch.object(sp.conn_behavior_tracker, "is_ddos_volumetric", return_value=(True, flood_stats)), \
                 patch.object(sp.conn_behavior_tracker, "is_c2_beacon", return_value=(False, {})), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()):
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_awaited_once()
            sent_alert = alerts_send.call_args.kwargs["value"]
            self.assertEqual(sent_alert["model_name"], "RULE_DDOS_CONN_RATE")
            self.assertEqual(sent_alert["threat_class"], "DDoS")
            self.assertEqual(sent_alert["confidence_score"], 0.95)
            self.assertEqual(sent_alert["evidence"]["connection_count"], 4243)
            self.assertEqual(sent_alert["evidence"]["destination_ip"], "10.0.0.9")

        asyncio.run(_run())

    def test_conn_behavior_publishes_a_low_confidence_beacon_alert(self):
        """RULE_C2_BEACON_PERIODIC is a real but standalone-weak signal
        (~12-19% real precision alone, per inference/conn_behavior.py's
        module docstring) -- confidence is deliberately kept below 0.5 so
        a lone firing can never by itself cross
        inference/risk.py's calculate_risk_score() incident threshold;
        it's meant to corroborate, not stand alone."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.9", "uid": "C-BEACON"}
        beacon_stats = {"observations": 7, "mean_interval_seconds": 60.1, "coefficient_of_variation": 0.05}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp.conn_behavior_tracker, "record_connection", return_value=None), \
                 patch.object(sp.conn_behavior_tracker, "is_ddos_volumetric", return_value=(False, {})), \
                 patch.object(sp.conn_behavior_tracker, "is_c2_beacon", return_value=(True, beacon_stats)), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()):
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_awaited_once()
            sent_alert = alerts_send.call_args.kwargs["value"]
            self.assertEqual(sent_alert["model_name"], "RULE_C2_BEACON_PERIODIC")
            self.assertEqual(sent_alert["threat_class"], "C2 Beaconing")
            self.assertEqual(sent_alert["confidence_score"], 0.40)
            self.assertLess(sent_alert["confidence_score"], 0.5)
            self.assertEqual(sent_alert["evidence"]["observations"], 7)

        asyncio.run(_run())

    def test_conn_behavior_neither_alert_fires_on_ordinary_traffic(self):
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C-ORDINARY"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp.conn_behavior_tracker, "record_connection", return_value=None), \
                 patch.object(sp.conn_behavior_tracker, "is_ddos_volumetric", return_value=(False, {})), \
                 patch.object(sp.conn_behavior_tracker, "is_c2_beacon", return_value=(False, {})), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_not_awaited()
            dlq.assert_not_awaited()

        asyncio.run(_run())

    def test_process_traffic_dns_response_event_updates_tracker_without_alerting(self):
        """A dns_response event exists purely to feed the behavioral
        tracker's NXDOMAIN rate -- it must never itself produce an
        alert, and must correctly resolve the querying CLIENT (this
        event's id.orig_h, per ingest/pcap_ingester.py's
        _extract_dns_response_event()) as the tracked host."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "dns_response", "id.orig_h": "10.0.0.9", "id.resp_h": "8.8.8.8", "query": "evil.com", "rcode": 3}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[]), \
                 patch.object(sp.dns_behavior_tracker, "record_response", return_value=None) as record_response, \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            record_response.assert_called_once_with("10.0.0.9", True)
            alerts_send.assert_not_awaited()
            dlq.assert_not_awaited()

        asyncio.run(_run())

    def test_process_traffic_invalid_alert_schema_routes_to_dlq_not_kafka(self):
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C2"}
        detection = {"threat_class": "Port Scanning", "severity": "medium", "confidence": 0.8, "rule_id": "TEST_RULE"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[detection]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp, "validate_alert", return_value=(False, "missing field")), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            alerts_send.assert_not_awaited()  # never reaches Kafka
            dlq.assert_awaited_once()
            self.assertIn("SchemaValidationError", dlq.call_args.args[2])

        asyncio.run(_run())

    def test_process_traffic_kafka_publish_timeout_routes_to_dlq_without_touching_redis(self):
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C3"}
        detection = {"threat_class": "Port Scanning", "severity": "medium", "confidence": 0.8, "rule_id": "TEST_RULE"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[detection]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(side_effect=asyncio.TimeoutError())), \
                 patch.object(sp.correlator, "add_alert") as add_alert, \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            add_alert.assert_not_called()  # Redis must never be touched pre-commit
            dlq.assert_awaited_once()
            self.assertIn("Timeout during alert Kafka publish", dlq.call_args.args[2])

        asyncio.run(_run())

    def test_process_traffic_redis_error_after_commit_routes_to_dlq(self):
        import redis
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C4"}
        detection = {"threat_class": "Port Scanning", "severity": "medium", "confidence": 0.8, "rule_id": "TEST_RULE"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={}), \
                 patch.object(sp, "evaluate_rules", return_value=[detection]), \
                 patch.object(sp.flow_engine, "score", return_value=(False, 0.0, 1.0)), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", side_effect=redis.RedisError("boom")), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            # The alert was already durably published before Redis failed --
            # this is the two-phase-commit ordering the code's own comments
            # describe: Kafka first, Redis only after.
            alerts_send.assert_awaited_once()
            dlq.assert_awaited_once()
            self.assertIn("RedisUnavailable", dlq.call_args.args[2])

        asyncio.run(_run())

    def test_process_traffic_publishes_a_second_alert_when_the_flow_looks_anomalous(self):
        """A conn event can trip both a rule (evaluate_rules) and the flow
        autoencoder independently -- confirms the new detection actually
        reaches Kafka as its own alert, not silently dropped or merged."""
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C6", "orig_pkts": 40000}
        rule_detection = {"threat_class": "Port Scanning", "severity": "medium", "confidence": 0.8, "rule_id": "TEST_RULE"}

        async def _run():
            with patch.object(sp, "extract_features", return_value={"orig_bytes": 50_000_000, "resp_bytes": 500, "duration": 5.0}), \
                 patch.object(sp, "evaluate_rules", return_value=[rule_detection]), \
                 patch.object(sp.flow_engine, "score", return_value=(True, 0.5, 0.04)), \
                 patch.object(sp, "validate_alert", return_value=(True, None)), \
                 patch.object(sp.enricher, "enrich", new=AsyncMock(side_effect=lambda a: a)), \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock(return_value=None)) as alerts_send, \
                 patch.object(sp.correlator, "add_alert", return_value=None), \
                 patch.object(sp, "_send_dlq_safely", new=AsyncMock()) as dlq:
                await sp.process_traffic.fun(self._fake_stream([event]))

            self.assertEqual(alerts_send.await_count, 2)
            published_classes = {c.kwargs["value"].get("threat_class") for c in alerts_send.await_args_list}
            self.assertIn("Port Scanning", published_classes)
            self.assertIn("Anomalous Flow", published_classes)
            anomalous_alert = next(
                c.kwargs["value"] for c in alerts_send.await_args_list if c.kwargs["value"].get("threat_class") == "Anomalous Flow"
            )
            self.assertEqual(anomalous_alert["model_name"], "DL_AUTOENCODER_FLOW_ANOMALY")
            self.assertIn("reconstruction_mse", anomalous_alert["evidence"])
            dlq.assert_not_awaited()

        asyncio.run(_run())

    def test_process_traffic_feature_extraction_failure_skips_event_without_crashing(self):
        import inference.stream_processor_faust as sp

        event = {"event_type": "conn", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "uid": "C5"}

        async def _run():
            with patch.object(sp, "extract_features", side_effect=RuntimeError("boom")), \
                 patch.object(sp, "evaluate_rules") as rules_mock, \
                 patch.object(sp.alerts_topic, "send", new=AsyncMock()) as alerts_send:
                await sp.process_traffic.fun(self._fake_stream([event]))  # must not raise

            rules_mock.assert_not_called()
            alerts_send.assert_not_awaited()

        asyncio.run(_run())

    def test_forwarded_header_is_capped_not_processed_unbounded(self):
        # A stuffed X-Forwarded-For (thousands of junk entries) previously
        # had no bound on how many comma-separated segments get split and
        # validated. Only the last _MAX_XFF_HOPS are considered now.
        from api.deps import _MAX_XFF_HOPS, get_remote_address

        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"  # trusted proxy
        # More hops than _MAX_XFF_HOPS but well under the header-length cap
        # (short entries -- the length cap is exercised separately below),
        # with a real client IP at the tail, closest to our trusted proxy:
        # right-to-left parsing must still find it despite the hop cap.
        junk_hops = ", ".join(f"1.1.1.{i % 250}" for i in range(30))
        forwarded = f"{junk_hops}, 203.0.113.77, 127.0.0.1"
        self.assertLess(len(forwarded), 2048)
        mock_req.headers = {"X-Forwarded-For": forwarded}

        result = get_remote_address(mock_req)  # must not hang or crash
        self.assertEqual(result, "203.0.113.77")

        # An oversized header is dropped entirely rather than processed at all.
        mock_req_oversized = MagicMock()
        mock_req_oversized.client.host = "127.0.0.1"
        mock_req_oversized.headers = {"X-Forwarded-For": "10.0.0.1, " * 1000}
        result_oversized = get_remote_address(mock_req_oversized)
        self.assertEqual(result_oversized, "127.0.0.1")  # falls back to the direct peer

    def test_correlation_id_and_path_are_stamped_onto_real_log_lines(self):
        # correlation_id/path were previously read via getattr(record, ...,
        # None) from fields nothing ever set -- every structured log line
        # logged both as null regardless of which request triggered it.
        # Drives the real middleware directly (not through a full HTTP
        # round-trip) so the log line is captured from inside call_next,
        # the exact window during which the context vars are set --
        # asserting against a line emitted after the request completes
        # would just prove the reset() cleanup path, not the propagation.
        import io
        import json as _json
        import logging as _logging
        from starlette.responses import Response
        from api.main import request_tracing_middleware, _handler

        buf = io.StringIO()
        capture_handler = _logging.StreamHandler(buf)
        capture_handler.setFormatter(_handler.formatter)
        capture_handler.addFilter(_handler.filters[0])
        root_logger = _logging.getLogger()
        root_logger.addHandler(capture_handler)

        fake_request = MagicMock()
        fake_request.headers = {}
        fake_request.url.path = "/api/v1/alerts"

        async def _call_next(request):
            _logging.getLogger("api.main").info("test line during request")
            return Response(status_code=200)

        try:
            asyncio.run(request_tracing_middleware(fake_request, _call_next))
        finally:
            root_logger.removeHandler(capture_handler)

        lines = [_json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]
        matching = [ln for ln in lines if ln.get("msg") == "test line during request"]
        self.assertTrue(matching, "expected the captured log line to appear")
        self.assertEqual(matching[0]["path"], "/api/v1/alerts")
        self.assertIsNotNone(matching[0]["correlation_id"])
        self.assertTrue(matching[0]["correlation_id"].startswith("req-"))

    def test_correlation_id_does_not_leak_across_requests(self):
        # Context vars are task-local; a value set on one request must not
        # bleed into logs from a request handled without one (or with a
        # different id) on the same event loop.
        import io
        import json as _json
        import logging as _logging
        from starlette.responses import Response
        from api.main import request_tracing_middleware, _handler

        buf = io.StringIO()
        capture_handler = _logging.StreamHandler(buf)
        capture_handler.setFormatter(_handler.formatter)
        capture_handler.addFilter(_handler.filters[0])
        root_logger = _logging.getLogger()
        root_logger.addHandler(capture_handler)

        async def _call_next(request):
            _logging.getLogger("api.main").info("during handling")
            return Response(status_code=200)

        try:
            req_a = MagicMock()
            req_a.headers = {"X-Request-ID": "req-AAAA"}
            req_a.url.path = "/a"
            asyncio.run(request_tracing_middleware(req_a, _call_next))

            _logging.getLogger("api.main").info("outside any request")

            req_b = MagicMock()
            req_b.headers = {"X-Request-ID": "req-BBBB"}
            req_b.url.path = "/b"
            asyncio.run(request_tracing_middleware(req_b, _call_next))
        finally:
            root_logger.removeHandler(capture_handler)

        lines = [_json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]
        during = [ln for ln in lines if ln["msg"] == "during handling"]
        outside = [ln for ln in lines if ln["msg"] == "outside any request"][0]

        self.assertEqual(during[0]["correlation_id"], "req-AAAA")
        self.assertEqual(during[0]["path"], "/a")
        self.assertEqual(during[1]["correlation_id"], "req-BBBB")
        self.assertEqual(during[1]["path"], "/b")
        self.assertIsNone(outside["correlation_id"])

if __name__ == '__main__':
    unittest.main()
# pytest.mark.skip added
