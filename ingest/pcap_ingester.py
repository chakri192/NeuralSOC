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
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    from kafka import KafkaProducer
except ImportError:
    print("Please install scapy and kafka-python: pip install scapy kafka-python")
    sys.exit(1)

def ingest_pcap(pcap_file: str, broker: str = "localhost:9092", topic: str = "security_alerts"):
    print(f"[*] Initializing Raw PCAP Ingestion Pipeline...")
    print(f"[*] Target Broker: {broker} | Topic: {topic}")
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file '{pcap_file}' not found.")
        return

    try:
        producer = KafkaProducer(
            bootstrap_servers=broker.split(","),
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
    except Exception as e:
        print(f"[!] Failed to connect to Kafka: {e}")
        return

    print(f"[*] Reading raw packets from {pcap_file} (This may take a moment...)")
    packets = rdpcap(pcap_file)
    
    # State tracking to build "flows" out of raw packets
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

    print(f"[*] Extracted {len(packets)} raw packets. Reassembling into network flows...")
    
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "other"
            
            if proto in ["tcp", "udp"]:
                src_port = pkt[proto].sport
                dst_port = pkt[proto].dport
                
                # Flow key (directional)
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
                
                pkt_time = float(pkt.time)
                pkt_len = len(pkt)
                
                if reverse_key in flows:
                    # This packet is a response
                    flows[reverse_key]["resp_pkts"] += 1
                    flows[reverse_key]["resp_bytes"] += pkt_len
                    flows[reverse_key]["duration"] = pkt_time - flows[reverse_key]["start_time"]
                else:
                    # This packet is an origination
                    f = flows[flow_key]
                    if f["start_time"] is None:
                        f["start_time"] = pkt_time
                        f["id.orig_h"] = src_ip
                        f["id.orig_p"] = src_port
                        f["id.resp_h"] = dst_ip
                        f["id.resp_p"] = dst_port
                        f["proto"] = proto
                        f["service"] = "unknown"
                        f["conn_state"] = "SF"
                    
                    f["orig_pkts"] += 1
                    f["orig_bytes"] += pkt_len
                    f["duration"] = pkt_time - f["start_time"]

    print(f"[*] Reassembled {len(flows)} unique network flows.")
    print("[*] Streaming to AI Engine via Kafka...")
    
    for key, flow_data in flows.items():
        # Remove internal tracking variables
        if "start_time" in flow_data:
            del flow_data["start_time"]
            
        producer.send(topic, flow_data)
        print(f"   -> Streamed Flow: {flow_data['id.orig_h']} -> {flow_data['id.resp_h']}")
        time.sleep(0.05) # Slight delay to simulate real-time streaming
        
    producer.flush()
    print("[*] PCAP Ingestion Complete. All raw traffic successfully streamed to AI.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest raw PCAP file into Kafka")
    parser.add_argument("pcap", help="Path to the .pcap file")
    parser.add_argument("--broker", default="localhost:9092", help="Kafka broker")
    args = parser.parse_args()
    
    ingest_pcap(args.pcap, args.broker)
