#!/usr/bin/env python3
"""
simulate_zeek_feed.py
=====================
High-Fidelity Zeek Log Stream Generator for Hackathon Demo & Stress Testing.

Generates realistic background enterprise traffic alongside active attacks
for all 6 required threat categories:
a. Volumetric / Protocol DDoS (TCP SYN flood bursts & UDP amplification)
b. Botnet C2 Beaconing (Periodic heartbeat connections with low jitter)
c. DGA Domains & DNS Tunnelling (Hex/Base64 encoded long TXT queries)
d. Encrypted Malware Sessions (Cobalt Strike, Sliver, Metasploit JA3s)
e. Reconnaissance & Port Scanning (Vertical port scans & horizontal sweeps)
f. Data Exfiltration (Asymmetric high-volume unidirectional uploads)
"""

import os
import sys
import time
import json
import random
import string
import argparse
from typing import Dict, Any

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "zeek_logs")
os.makedirs(LOG_DIR, exist_ok=True)

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 80)]
EXTERNAL_BENIGN_IPS = ["142.250.190.46", "140.82.121.4", "13.107.42.14", "151.101.1.140", "104.244.42.1"]
MALICIOUS_C2_IPS = ["198.51.100.44", "203.0.113.88", "185.220.101.5", "45.154.255.9"]
INFECTED_HOST_BEACON = "192.168.1.33"
ATTACKER_SCANNER_IP = "192.168.1.99"

BENIGN_DOMAINS = [
    "www.google.com", "api.github.com", "login.microsoftonline.com", "cdn.cloudflare.net",
    "s3.amazonaws.com", "slack.com", "registry.npmjs.org", "en.wikipedia.org"
]

MALICIOUS_JA3_LIST = [
    "a0e9f5d64349fb13191bc781f81f42e1", # Cobalt Strike
    "72a589da586844d7f0818ce684948eea", # Sliver C2
    "51c64c77e60f39ac3e179284d623b05e", # Metasploit
]

BENIGN_JA3_LIST = [
    "cd08e31494f9531f491fc72642953f76", # Chrome
    "66918128f1b9b03303d77c6f2eefd128", # Firefox
    "2023d8c1c4f5539433604f0da99c381c", # Safari
]


def generate_flow_uid():
    chars = string.ascii_letters + string.digits
    return "C" + "".join(random.choices(chars, k=17))


def write_json_log(log_name: str, record: dict):
    filepath = os.path.join(LOG_DIR, f"{log_name}.log")
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()


def simulate_normal_flow():
    uid = generate_flow_uid()
    src_ip = random.choice(INTERNAL_IPS)
    dst_ip = random.choice(EXTERNAL_BENIGN_IPS)
    src_port = random.randint(30000, 65000)
    domain = random.choice(BENIGN_DOMAINS)
    now = time.time()
    
    write_json_log("dns", {
        "ts": now,
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": src_port,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "query": domain,
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": [dst_ip],
    })
    
    write_json_log("ssl", {
        "ts": now,
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": src_port,
        "id.resp_h": dst_ip,
        "id.resp_p": 443,
        "version": "TLSv13",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "server_name": domain,
        "ja3": random.choice(BENIGN_JA3_LIST),
        "validation_status": "ok",
    })
    
    write_json_log("conn", {
        "ts": now,
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": src_port,
        "id.resp_h": dst_ip,
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": round(random.uniform(0.2, 2.5), 3),
        "orig_bytes": random.randint(1200, 6000),
        "resp_bytes": random.randint(5000, 80000),
        "conn_state": "SF",
        "orig_pkts": random.randint(8, 25),
        "resp_pkts": random.randint(12, 50),
    })


# ----------------------------------------------------------------------
# Attack Generators for All 6 Categories
# ----------------------------------------------------------------------

def simulate_ddos_syn_flood():
    """Threat Class a: Volumetric / Protocol DDoS (SYN Flood)"""
    uid = generate_flow_uid()
    victim_ip = "192.168.1.1"
    spoofed_ip = f"172.16.{random.randint(1,250)}.{random.randint(1,250)}"
    write_json_log("conn", {
        "ts": time.time(),
        "uid": uid,
        "id.orig_h": spoofed_ip,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": victim_ip,
        "id.resp_p": 80,
        "proto": "tcp",
        "duration": 0.001,
        "orig_bytes": 0,
        "resp_bytes": 0,
        "conn_state": "S0", # Uncompleted SYN
        "orig_pkts": random.randint(150, 500),
        "resp_pkts": 0,
    })
    print(f"🌊 [DDoS] Simulated SYN Flood: {spoofed_ip} -> {victim_ip}:80")


def simulate_c2_beaconing():
    """Threat Class b: Botnet C2 Beaconing (Regular Heartbeat)"""
    uid = generate_flow_uid()
    c2_ip = "185.220.101.5"
    now = time.time()
    write_json_log("conn", {
        "ts": now,
        "uid": uid,
        "id.orig_h": INFECTED_HOST_BEACON,
        "id.orig_p": 49152,
        "id.resp_h": c2_ip,
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 0.12,
        "orig_bytes": 256,
        "resp_bytes": 128,
        "conn_state": "SF",
        "orig_pkts": 4,
        "resp_pkts": 4,
    })
    print(f"💓 [Beacon] Simulated C2 Heartbeat: {INFECTED_HOST_BEACON} -> {c2_ip}:443")


def simulate_dga_and_tunneling():
    """Threat Class c: DGA and DNS Tunnelling"""
    uid = generate_flow_uid()
    src_ip = random.choice(INTERNAL_IPS)
    
    if random.random() < 0.5:
        # DGA Query
        dga_body = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(16, 24)))
        tld = random.choice(["cc", "xyz", "top", "buzz", "click"])
        query = f"{dga_body}.{tld}"
        write_json_log("dns", {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(40000, 65000),
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": query,
            "qtype_name": "A",
            "rcode_name": "NXDOMAIN",
        })
        print(f"🎲 [DGA] Simulated DGA Query: {query} from {src_ip}")
    else:
        # DNS Tunneling / Exfiltration Query
        hex_payload = "".join(random.choices("0123456789abcdef", k=48))
        tunnel_query = f"exfil.{hex_payload}.tunnel-c2.net"
        write_json_log("dns", {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(40000, 65000),
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": tunnel_query,
            "qtype_name": "TXT",
            "rcode_name": "NOERROR",
        })
        print(f"🚇 [Tunnel] Simulated DNS Tunneling Payload: {tunnel_query[:35]}... from {src_ip}")


def simulate_c2_ja3_malware():
    """Threat Class d: Malware in Encrypted Session (JA3)"""
    uid = generate_flow_uid()
    src_ip = random.choice(INTERNAL_IPS)
    c2_ip = random.choice(MALICIOUS_C2_IPS)
    ja3 = random.choice(MALICIOUS_JA3_LIST)
    
    write_json_log("ssl", {
        "ts": time.time(),
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": random.randint(45000, 65000),
        "id.resp_h": c2_ip,
        "id.resp_p": 443,
        "version": "TLSv12",
        "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "server_name": "cdn-cloud-update-service.com",
        "ja3": ja3,
        "validation_status": "self signed certificate",
    })
    print(f"🚨 [JA3] Simulated C2 TLS Handshake: {ja3} to {c2_ip}")


def simulate_port_scan():
    """Threat Class e: Reconnaissance & Port Scanning"""
    target_ip = "192.168.1.50"
    ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    now = time.time()
    for port in ports:
        uid = generate_flow_uid()
        write_json_log("conn", {
            "ts": now,
            "uid": uid,
            "id.orig_h": ATTACKER_SCANNER_IP,
            "id.orig_p": random.randint(50000, 65000),
            "id.resp_h": target_ip,
            "id.resp_p": port,
            "proto": "tcp",
            "duration": 0.002,
            "orig_bytes": 0,
            "resp_bytes": 0,
            "conn_state": "REJ",
            "orig_pkts": 1,
            "resp_pkts": 1,
        })
    print(f"🔎 [Recon] Simulated Vertical Port Scan: {ATTACKER_SCANNER_IP} scanning {len(ports)} ports on {target_ip}")


def simulate_data_exfiltration():
    """Threat Class f: Data Exfiltration (High Volume Asymmetric Outbound)"""
    uid = generate_flow_uid()
    src_ip = random.choice(INTERNAL_IPS)
    dest_ip = random.choice(MALICIOUS_C2_IPS)
    exfil_bytes = random.randint(35000000, 95000000)
    
    write_json_log("conn", {
        "ts": time.time(),
        "uid": uid,
        "id.orig_h": src_ip,
        "id.orig_p": random.randint(50000, 65000),
        "id.resp_h": dest_ip,
        "id.resp_p": 8443,
        "proto": "tcp",
        "service": "ssl",
        "duration": round(random.uniform(3.0, 10.0), 2),
        "orig_bytes": exfil_bytes,
        "resp_bytes": 140,
        "conn_state": "SF",
        "orig_pkts": int(exfil_bytes / 1400),
        "resp_pkts": 4,
    })
    print(f"💥 [Exfil] Simulated Data Exfiltration: {exfil_bytes / (1024*1024):.1f} MB from {src_ip} -> {dest_ip}")


def main():
    parser = argparse.ArgumentParser(description="Simulate Zeek JSON stream for testing all 6 threat categories.")
    parser.add_argument("--rate", type=float, default=3.0, help="Events generated per second")
    parser.add_argument("--burst-attacks", action="store_true", help="Increase attack frequency for demo")
    args = parser.parse_args()

    print(f"[*] Starting Zeek log stream simulation in {LOG_DIR}")
    print(f"[*] Rate: {args.rate} events/sec. Testing 6 Threat Classes:")
    print("    a. Volumetric DDoS (SYN Flood & UDP Amplification)")
    print("    b. Botnet C2 Beaconing (Regular Heartbeats)")
    print("    c. DGA Domains & DNS Tunnelling")
    print("    d. Encrypted Malware Sessions (JA3/JA4)")
    print("    e. Reconnaissance & Port Scanning")
    print("    f. Data Exfiltration")
    print("[*] Press Ctrl+C to stop.\n")

    sleep_sec = 1.0 / max(0.1, args.rate)
    step = 0

    try:
        while True:
            step += 1
            simulate_normal_flow()
            
            # Beacon pulse every ~5 steps
            if step % 5 == 0:
                simulate_c2_beaconing()

            # Attacks every few steps
            attack_freq = 6 if args.burst_attacks else 12
            if step % attack_freq == 0:
                choice = random.choice(["ddos", "dga_tunnel", "ja3", "scan", "exfil"])
                if choice == "ddos":
                    simulate_ddos_syn_flood()
                elif choice == "dga_tunnel":
                    simulate_dga_and_tunneling()
                elif choice == "ja3":
                    simulate_c2_ja3_malware()
                elif choice == "scan":
                    simulate_port_scan()
                elif choice == "exfil":
                    simulate_data_exfiltration()

            time.sleep(sleep_sec)
    except KeyboardInterrupt:
        print("\n[*] Simulation stopped.")


if __name__ == "__main__":
    main()
