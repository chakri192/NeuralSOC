#!/usr/bin/env python3
"""
pcap_ingester.py
================
Enterprise Production Proof-of-Concept.
This script proves that the system can process RAW network traffic (bytes on a wire)
by reading a standard .pcap file, extracting the metadata (like Zeek does),
and pushing it directly into our Kafka/Redpanda pipeline.
"""

import os
import sys
import time
import json
import uuid
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, UDP
    from kafka import KafkaProducer
except ImportError:
    print("Please install scapy and kafka-python: pip install scapy kafka-python")
    sys.exit(1)

def _emit_flow(producer, topic, key, payload, log):
    """Shared size-guarded send -- previously the 5MB guard only existed
    on the periodic re-emission path; the final flush loop sent whatever
    size payload it had with no check at all."""
    try:
        payload_str = json.dumps(payload)
        if len(payload_str.encode('utf-8')) > 5 * 1024 * 1024:
            raise ValueError('Payload exceeds 5MB')
        producer.send(topic, payload)
    except Exception as send_err:
        log.error(f"Failed to stream flow {key}: {send_err}")


def ingest_pcap(pcap_file: str, broker: str = "localhost:9092", topic: str = "raw_traffic"):
    print(f"[*] Initializing Raw PCAP Ingestion Pipeline (STREAMING)...")
    print(f"[*] Target Broker: {broker} | Topic: {topic}")

    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file '{pcap_file}' not found.")
        return

    try:
        # STREAMING mode: process packets incrementally to avoid memory explosion
        from scapy.utils import PcapReader
        producer = KafkaProducer(
            bootstrap_servers=broker.split(","),
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=3,
            request_timeout_ms=5000
        )
    except Exception as e:
        print(f"[!] Failed to initialize streaming pipeline: {e}")
        return

    flows = defaultdict(lambda: {
        "ts": time.time(),
        "uid": str(uuid.uuid4()),
        "orig_bytes": 0,
        "resp_bytes": 0,
        "orig_pkts": 0,
        "resp_pkts": 0,
        "duration": 0.0,
        "start_time": None
    })

    MAX_FLOWS = 50000  # bound memory regardless of how long the capture runs
    MAX_PACKET_BYTES = 65535  # a single packet larger than this is not a normal Ethernet frame

    packet_count = 0
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                if len(pkt) > MAX_PACKET_BYTES:
                    logger.warning("Skipping oversized packet (%d bytes) at #%d", len(pkt), packet_count)
                    continue
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    # Scapy indexes layers by CLASS (pkt[TCP]), not by a
                    # lowercase string ("tcp") -- pkt["tcp"] raises
                    # IndexError on the very first packet, meaning this
                    # ingester previously parsed zero packets, ever.
                    if TCP in pkt:
                        proto, layer = "tcp", TCP
                    elif UDP in pkt:
                        proto, layer = "udp", UDP
                    else:
                        proto, layer = "other", None

                    if layer is not None:
                        src_port = pkt[layer].sport
                        dst_port = pkt[layer].dport
                        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                        reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
                        pkt_time = float(pkt.time)
                        pkt_len = len(pkt)

                        if reverse_key in flows:
                            flows[reverse_key]["resp_pkts"] += 1
                            flows[reverse_key]["resp_bytes"] += pkt_len
                            flows[reverse_key]["duration"] = pkt_time - flows[reverse_key]["start_time"]
                        else:
                            if flow_key not in flows:
                                f = {
                                    "start_time": pkt_time,
                                    "orig_pkts": 0,
                                    "orig_bytes": 0,
                                    "resp_pkts": 0,
                                    "resp_bytes": 0,
                                    "duration": 0,
                                    "id.orig_h": src_ip,
                                    "id.orig_p": src_port,
                                    "id.resp_h": dst_ip,
                                    "id.resp_p": dst_port,
                                    "proto": proto,
                                    "service": "unknown",
                                    "conn_state": "SF",
                                }
                                flows[flow_key] = f
                            f = flows[flow_key]
                            if f["start_time"] is None:
                                f["start_time"] = pkt_time
                            f["orig_pkts"] += 1
                            f["orig_bytes"] += pkt_len
                            f["duration"] = pkt_time - f["start_time"]

                        # STREAMING: emit flow periodically without destroying state
                        if packet_count % 500 == 0:
                            emitted = []
                            for key, flow_data in list(flows.items()):
                                if flow_data.get("start_time") is not None:
                                    emitted.append((key, dict(flow_data)))
                            for key, payload in emitted:
                                _emit_flow(producer, topic, key, payload, logger)

                        # Bound memory regardless of capture length: without
                        # this, `flows` (and the periodic full re-scan
                        # above) grow without limit for the life of the
                        # capture. Evict the oldest flows once over the cap,
                        # emitting each one final time as it's evicted.
                        if len(flows) > MAX_FLOWS:
                            oldest_first = sorted(
                                flows.items(),
                                key=lambda kv: kv[1].get("start_time") or 0,
                            )
                            for key, flow_data in oldest_first[: len(flows) - MAX_FLOWS]:
                                payload = dict(flow_data)
                                payload.pop("start_time", None)
                                _emit_flow(producer, topic, key, payload, logger)
                                del flows[key]

        # Final flush for remaining flows
        for key, flow_data in flows.items():
            payload = dict(flow_data)
            payload.pop("start_time", None)
            _emit_flow(producer, topic, key, payload, logger)

        producer.flush()
        print(f"[*] Streaming Complete. {packet_count} packets processed; flows emitted incrementally.")
    except Exception as e:
        print(f"[!] Streaming failure: {e}")
        return

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest raw PCAP file into Kafka")
    parser.add_argument("pcap", help="Path to the .pcap file")
    parser.add_argument("--broker", default="localhost:9092", help="Kafka broker")
    parser.add_argument("--topic", default="raw_traffic", help="Kafka topic")
    args = parser.parse_args()
    
    ingest_pcap(args.pcap, args.broker, args.topic)
