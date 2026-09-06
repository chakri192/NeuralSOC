"""ingest/simulator.py had 0% coverage. It constructs a real KafkaProducer
at import time (connecting to REDPANDA_BROKERS, exiting the process on
failure), so kafka.KafkaProducer must be patched BEFORE the module is
first imported -- otherwise merely importing it in a test environment
with no reachable broker crashes with SystemExit.
"""
import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

with patch("kafka.KafkaProducer", return_value=MagicMock()):
    import ingest.simulator as simulator


def test_generate_conn_log_normal_traffic_shape():
    event = simulator.generate_conn_log(is_attack=False)
    assert event["conn_state"] == "SF"
    assert event["attack_label"] == "normal"
    assert event["event_type"] == "conn"
    assert "ja4" not in event


def test_generate_conn_log_reconnaissance_scan_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="reconnaissance")
    assert event["conn_state"] == "S0"
    assert 1 <= event["orig_pkts"] <= 3
    assert 1 <= event["id.resp_p"] <= 1024
    assert event["attack_label"] == "reconnaissance"


def test_generate_conn_log_ddos_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="ddos")
    assert event["conn_state"] == "REJ"
    assert event["orig_pkts"] >= 15000


def test_generate_conn_log_data_exfiltration_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="data_exfiltration")
    assert event["orig_bytes"] >= 6_000_000
    assert event["resp_bytes"] <= 5000


def test_generate_conn_log_encrypted_malware_ja4_matches_the_calibrated_rule():
    # This exact fingerprint is what inference/rules.py's JA4 rule was
    # recalibrated against -- if either side drifts, detection silently
    # stops firing on the simulator's own demo traffic.
    event = simulator.generate_conn_log(is_attack=True, attack_type="encrypted_malware")
    assert event["ja4"] == "t13d000000_rare_fingerprint"


def test_generate_dns_log_normal_traffic():
    event = simulator.generate_dns_log(is_attack=False)
    assert event["query"] in ["google.com", "apple.com", "cloudflare.com"]
    assert event["rcode"] == 0
    assert event["rcode_name"] == "NOERROR"


def test_generate_dns_log_dga_tunnelling_shape():
    event = simulator.generate_dns_log(is_attack=True, attack_type="dga_dns_tunnelling")
    assert event["query"].endswith(".malicious-tunnel.com")
    assert event["qtype_name"] == "TXT"
    assert event["attack_label"] == "dga_dns_tunnelling"


def test_generate_conn_log_c2_beaconing_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="c2_beaconing")
    assert event["id.resp_p"] in (4444, 8080, 1337)
    assert 60 <= event["orig_bytes"] <= 120
    assert 60 <= event["resp_bytes"] <= 120


def test_producer_construction_failure_exits_process():
    # The module-level try/except around KafkaProducer(...) is the only
    # thing standing between a broker outage and an unhandled traceback --
    # it must exit cleanly (sys.exit(1)), not crash with the raw exception.
    with patch("kafka.KafkaProducer", side_effect=RuntimeError("broker unreachable")):
        with pytest.raises(SystemExit) as exc_info:
            importlib.reload(simulator)
    assert exc_info.value.code == 1
    # Restore the real (mocked) module state for any test running after this one.
    with patch("kafka.KafkaProducer", return_value=MagicMock()):
        importlib.reload(simulator)


class TestMain:
    """main()'s while-True loop has no externally settable stop condition
    except its own KeyboardInterrupt handler -- drive it with a fake
    time.sleep that raises KeyboardInterrupt after a few iterations,
    exercising the real scenario/attack-type selection and burst/normal
    branches instead of only the two generator functions directly."""

    def _run_main_for_n_events(self, monkeypatch, argv, n=20):
        monkeypatch.setattr(sys, "argv", argv)
        calls = {"n": 0}

        def fake_sleep(_seconds):
            calls["n"] += 1
            if calls["n"] >= n:
                raise KeyboardInterrupt()

        monkeypatch.setattr(simulator.time, "sleep", fake_sleep)
        simulator.producer.reset_mock()
        simulator.main()  # must return (via KeyboardInterrupt), not hang
        return simulator.producer

    def test_main_mixed_scenario_produces_and_flushes_on_interrupt(self, monkeypatch):
        producer = self._run_main_for_n_events(
            monkeypatch, ["simulator.py", "--scenario", "mixed", "--seed", "1"]
        )
        assert producer.send.call_count >= 1
        producer.flush.assert_called()

    def test_main_normal_scenario_uses_rate_based_sleep(self, monkeypatch):
        producer = self._run_main_for_n_events(
            monkeypatch, ["simulator.py", "--scenario", "normal", "--rate", "50", "--seed", "2"]
        )
        # Every produced event in "normal" mode must carry attack_label "normal".
        sent_events = [call.kwargs.get("value") for call in producer.send.call_args_list]
        assert sent_events and all(e["attack_label"] == "normal" for e in sent_events)

    def test_main_burst_mode_still_stops_on_interrupt(self, monkeypatch):
        producer = self._run_main_for_n_events(
            monkeypatch, ["simulator.py", "--burst", "--scenario", "port_scan", "--seed", "3"], n=10
        )
        assert producer.send.call_count >= 1

    def test_main_single_attack_scenario_labels_every_attack_event(self, monkeypatch):
        # A non-"mixed" attack scenario takes the `attack_type = args.scenario`
        # branch directly (rather than randomly picking one of six types),
        # and running past 100 events exercises the periodic progress print
        # and the every-5000 producer.flush() call.
        producer = self._run_main_for_n_events(
            monkeypatch, ["simulator.py", "--scenario", "dga", "--seed", "7"], n=150
        )
        sent_events = [call.kwargs.get("value") for call in producer.send.call_args_list]
        attack_events = [e for e in sent_events if e["attack_label"] not in ("normal", "")]
        assert attack_events and all(e["attack_label"] == "dga" for e in attack_events)
