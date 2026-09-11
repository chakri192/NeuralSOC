"""ingest/pcap_ingester.py had 0% direct test coverage. Synthetic pcap
files are built in-memory with Scapy's own packet classes and written via
wrpcap() to a temp file, then fed through the real ingest_pcap() -- this
exercises the real scapy parsing path (pkt[IP], pkt[TCP]/pkt[UDP] layer
indexing, flow-key bidirectional matching) rather than mocking scapy away.
"""
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

from ingest.pcap_ingester import _emit_flow, ingest_pcap


class TestEmitFlow:
    def test_sends_a_normal_payload(self):
        producer = MagicMock()
        _emit_flow(producer, "raw_traffic", "key1", {"a": 1}, MagicMock())
        producer.send.assert_called_once_with("raw_traffic", {"a": 1})

    def test_oversized_payload_is_rejected_not_sent(self):
        producer = MagicMock()
        huge_payload = {"data": "x" * (6 * 1024 * 1024)}
        log = MagicMock()
        _emit_flow(producer, "raw_traffic", "key1", huge_payload, log)
        producer.send.assert_not_called()
        log.error.assert_called_once()

    def test_producer_send_exception_is_logged_not_raised(self):
        producer = MagicMock()
        producer.send.side_effect = RuntimeError("broker down")
        log = MagicMock()
        _emit_flow(producer, "raw_traffic", "key1", {"a": 1}, log)  # must not raise
        log.error.assert_called_once()

    def test_unserializable_payload_is_logged_not_raised(self):
        producer = MagicMock()
        log = MagicMock()
        _emit_flow(producer, "raw_traffic", "key1", {"a": object()}, log)  # must not raise
        log.error.assert_called_once()


class TestIngestPcap:
    def test_missing_pcap_file_returns_early(self, tmp_path):
        with patch("ingest.pcap_ingester.KafkaProducer") as mock_producer_cls:
            ingest_pcap(str(tmp_path / "does-not-exist.pcap"))
            mock_producer_cls.assert_not_called()

    def test_producer_construction_failure_returns_early(self, tmp_path):
        pcap_path = tmp_path / "empty.pcap"
        wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP()])
        with patch("ingest.pcap_ingester.KafkaProducer", side_effect=RuntimeError("no broker")):
            ingest_pcap(str(pcap_path))  # must not raise

    def test_bidirectional_tcp_flow_is_tracked_and_emitted(self, tmp_path):
        pcap_path = tmp_path / "tcp.pcap"
        pkts = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
            IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234),  # response, matches reverse_key
        ]
        wrpcap(str(pcap_path), pkts)

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        fake_producer.flush.assert_called_once()
        sent_flows = [call.args[1] for call in fake_producer.send.call_args_list]
        assert any(f.get("orig_pkts") == 1 and f.get("resp_pkts") == 1 for f in sent_flows)

    def test_conn_flows_carry_event_type_conn(self, tmp_path):
        """Regression test: every rule in inference/rules.py and every
        extractor in inference/features.py gates on
        event.get("event_type") == "conn" -- without this key, nothing
        this ingester ever emitted was reachable by any connection-based
        rule at all, confirmed by actually running a real malware pcap
        through the live pipeline and getting zero detections back."""
        pcap_path = tmp_path / "tcp.pcap"
        wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)])

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        sent_flows = [call.args[1] for call in fake_producer.send.call_args_list]
        assert any(f.get("event_type") == "conn" for f in sent_flows)

    def test_dns_query_is_emitted_as_its_own_dns_event(self, tmp_path):
        pcap_path = tmp_path / "dns.pcap"
        dns_query = (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=5353, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="xqzjk7fake-dga.example.com"))
        )
        wrpcap(str(pcap_path), [dns_query])

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        sent_flows = [call.args[1] for call in fake_producer.send.call_args_list]
        dns_events = [f for f in sent_flows if f.get("event_type") == "dns"]
        assert len(dns_events) == 1
        assert dns_events[0]["query"] == "xqzjk7fake-dga.example.com"
        assert dns_events[0]["qtype_name"] == "A"

    def test_dns_response_is_not_emitted_as_a_query(self, tmp_path):
        """qr=1 marks a DNS *response*, not a query -- inference/rules.py's
        entropy/tunnelling checks are about what a host asked for, not
        what a resolver answered with."""
        pcap_path = tmp_path / "dns_response.pcap"
        dns_response = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=5353)
            / DNS(qr=1, rd=1, qd=DNSQR(qname="example.com"))
        )
        wrpcap(str(pcap_path), [dns_response])

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        sent_flows = [call.args[1] for call in fake_producer.send.call_args_list]
        assert not any(f.get("event_type") == "dns" for f in sent_flows)

    def test_udp_flow_is_tracked(self, tmp_path):
        pcap_path = tmp_path / "udp.pcap"
        wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53)])

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        sent_flows = [call.args[1] for call in fake_producer.send.call_args_list]
        assert any(f.get("proto") == "udp" for f in sent_flows)

    def test_non_ip_packet_is_skipped_without_crashing(self, tmp_path):
        from scapy.all import ARP, Ether

        pcap_path = tmp_path / "no_ip.pcap"
        wrpcap(str(pcap_path), [Ether() / ARP()])  # no IP layer at all

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))  # must not raise
        fake_producer.send.assert_not_called()

    def test_ip_packet_with_no_tcp_or_udp_layer_is_not_tracked_as_a_flow(self, tmp_path):
        # A single, uniform linktype (raw IP, no Ethernet framing) --
        # mixing this with an Ethernet-framed packet in the same pcap file
        # would make PcapReader misinterpret one or the other's bytes,
        # since a pcap file declares one linktype for every packet in it.
        pcap_path = tmp_path / "other_proto.pcap"
        wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2")], linktype=101)  # LINKTYPE_RAW

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))  # must not raise
        fake_producer.send.assert_not_called()  # "other" proto is counted but never tracked as a flow

    def test_oversized_packet_is_skipped(self, tmp_path, monkeypatch):
        # IPv4's own 16-bit total-length field caps any packet Scapy can
        # actually *build* at 65535 bytes -- there's no way to construct a
        # genuinely larger one through the normal layer API to prove this
        # guard fires on a real capture. Lower MAX_PACKET_BYTES instead
        # (it's a plain module-level int the function reads via `len(pkt)
        # > MAX_PACKET_BYTES`) so an ordinary packet exercises the exact
        # same skip branch.
        import ingest.pcap_ingester as pcap_ingester_module
        monkeypatch.setattr(pcap_ingester_module, "MAX_PACKET_BYTES", 10)

        pcap_path = tmp_path / "oversized.pcap"
        oversized = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(load=b"x" * 100)
        normal_sized_but_still_over_the_lowered_cap = IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=3, dport=4)
        wrpcap(str(pcap_path), [oversized, normal_sized_but_still_over_the_lowered_cap])

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))  # must not raise; every packet here exceeds the lowered cap

        fake_producer.send.assert_not_called()  # both packets skipped -- nothing to track or emit

    def test_periodic_reemission_fires_past_500_packets(self, tmp_path):
        pcap_path = tmp_path / "burst.pcap"
        pkts = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80) for i in range(501)]
        wrpcap(str(pcap_path), pkts)

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        # 501 distinct flows (unique sport each) plus the periodic re-emission
        # at packet #500 means send() fires more than once per flow for at
        # least the flows seen before that checkpoint.
        assert fake_producer.send.call_count > 501

    def test_flows_are_evicted_once_over_max_flows(self, tmp_path, monkeypatch):
        import ingest.pcap_ingester as pcap_ingester_module
        monkeypatch.setattr(pcap_ingester_module, "MAX_FLOWS", 3)

        pcap_path = tmp_path / "many_flows.pcap"
        # 5 distinct flows (unique dport each), exceeding the lowered cap of 3.
        pkts = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=100 + i) for i in range(5)]
        wrpcap(str(pcap_path), pkts)

        fake_producer = MagicMock()
        with patch("ingest.pcap_ingester.KafkaProducer", return_value=fake_producer):
            ingest_pcap(str(pcap_path))

        # Every flow must have been emitted at least once -- either via
        # eviction mid-capture or the final flush -- none silently dropped.
        sent_flows = [call.args[1] for call in fake_producer.send.call_args_list]
        emitted_dports = {f["id.resp_p"] for f in sent_flows}
        assert emitted_dports == {100, 101, 102, 103, 104}

    def test_corrupted_pcap_file_is_handled_gracefully(self, tmp_path):
        pcap_path = tmp_path / "corrupt.pcap"
        pcap_path.write_bytes(b"this is not a real pcap file" * 10)

        with patch("ingest.pcap_ingester.KafkaProducer", return_value=MagicMock()):
            ingest_pcap(str(pcap_path))  # must not raise, even on a malformed file
