# TRAINING_ONLY_GUARD: all labels below are synthetic for benchmark/load-test ONLY
import os
import sys
import json
import time
import uuid
import random
import argparse
from kafka import KafkaProducer

BROKERS = os.getenv("REDPANDA_BROKERS", "127.0.0.1:9092")

try:
    producer = KafkaProducer(
        bootstrap_servers=[BROKERS],
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        retries=5
    )
except Exception as e:
    print(f"[Simulator] Failed to connect: {e}")
    sys.exit(1)

def generate_conn_log(is_attack=False, attack_type=""):
    src_ip = f"192.168.1.{random.randint(10,250)}"
    dst_ip = f"{random.randint(1,250)}.{random.randint(1,250)}.1.1"
    
    dst_port = random.choice([80, 443, 53])
    conn_state = "SF"
    orig_bytes = random.randint(100, 5000)
    resp_bytes = random.randint(100, 50000)
    orig_pkts = random.randint(5, 50)
    
    if is_attack:
        if attack_type == "reconnaissance":
            conn_state = "S0"
            orig_pkts = random.randint(1, 3)
            dst_port = random.randint(1, 1024)
        elif attack_type == "ddos":
            conn_state = "REJ"
            orig_pkts = random.randint(15000, 50000)
            dst_port = random.choice([80, 443])
        elif attack_type == "data_exfiltration":
            orig_bytes = random.randint(6000000, 15000000)
            resp_bytes = random.randint(100, 5000)
        elif attack_type == "c2_beaconing":
            orig_bytes = random.randint(60, 120)
            resp_bytes = random.randint(60, 120)
            dst_port = random.choice([4444, 8080, 1337])
            
    event = {
        "ts": time.time(),
        "uid": f"C{uuid.uuid4().hex[:18]}",
        "id.orig_h": src_ip,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dst_ip,
        "id.resp_p": dst_port,
        "proto": "tcp",
        "service": "http" if dst_port == 80 else ("ssl" if dst_port == 443 else "other"),
        "duration": random.uniform(0.1, 10.0),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": conn_state,
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": orig_pkts,
        "resp_pkts": random.randint(5, 50),
        "event_type": "conn",
        "sensor_id": "sim-01",
        "simulated": True,
        "attack_label": attack_type if is_attack else "normal"
    }

    if attack_type == "encrypted_malware":
        event["ja4"] = "t13d000000_rare_fingerprint"
        
    return event

def generate_dns_log(is_attack=False, attack_type=""):
    dga_domains = ["agjzzyxb.com", "login-microsoft-update-sec.com", "xn--faked-123.com"]
    normal_domains = ["google.com", "apple.com", "cloudflare.com"]
    
    if attack_type == "dga_dns_tunnelling":
        domain = f"{uuid.uuid4().hex}{uuid.uuid4().hex}{uuid.uuid4().hex}.malicious-tunnel.com"
        qtype_name = "TXT"
    else:
        domain = random.choice(dga_domains) if is_attack and "dga" in attack_type.lower() else random.choice(normal_domains)
        qtype_name = "A"
    
    return {
        "ts": time.time(),
        "uid": f"C{uuid.uuid4().hex[:18]}",
        "id.orig_h": f"192.168.1.{random.randint(10,250)}",
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": random.randint(1000, 65535),
        "rtt": random.uniform(0.01, 0.1),
        "query": domain,
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": 1 if qtype_name == "A" else 16,
        "qtype_name": qtype_name,
        "rcode": 0 if not is_attack else 3,
        "rcode_name": "NOERROR" if not is_attack else "NXDOMAIN",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": ["1.2.3.4"],
        "TTLs": [300],
        "rejected": False,
        "event_type": "dns",
        "sensor_id": "sim-01",
        "simulated": True,
        "attack_label": attack_type if is_attack else "normal"
    }

def main():
    parser = argparse.ArgumentParser(description="Synthetic Zeek Log Simulator")
    parser.add_argument("--burst", action="store_true", help="Enable high-throughput burst mode")
    parser.add_argument("--rate", type=float, default=1.0, help="Events per second in normal mode")
    parser.add_argument("--scenario", type=str, default="mixed", choices=["normal", "dga", "port_scan", "mixed"])
    parser.add_argument("--seed", type=int, default=None, help="Reproducible random seed")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    print(f"[Simulator] Started (Mode: {'BURST' if args.burst else 'NORMAL'}, Scenario: {args.scenario})")
    
    count = 0
    try:
        while True:
            is_attack = False
            attack_type = ""
            
            if args.scenario != "normal":
                if random.random() < 0.2: # 20% attack probability
                    is_attack = True
                    if args.scenario == "mixed":
                        attack_type = random.choice([
                            "dga_dns_tunnelling", 
                            "reconnaissance", 
                            "ddos", 
                            "data_exfiltration",
                            "encrypted_malware",
                            "c2_beaconing"
                        ])
                    else:
                        attack_type = args.scenario
            
            if is_attack:
                if attack_type in ["dga_dns_tunnelling"]:
                    event = generate_dns_log(is_attack, attack_type)
                else:
                    event = generate_conn_log(is_attack, attack_type)
            else:
                if random.random() < 0.3:
                    event = generate_dns_log(is_attack, attack_type)
                else:
                    event = generate_conn_log(is_attack, attack_type)
                
            producer.send("raw_traffic", value=event)
            count += 1
            
            if count % 100 == 0:
                print(f"[Simulator] Produced {count} events...")
            if count % 5000 == 0:
                producer.flush() # MEMORY FIX: Force RAM buffer to flush to Redpanda
                
            if not args.burst:
                time.sleep(1.0 / args.rate)
            else:
                time.sleep(0.001) # PERFORMANCE FIX: Prevent unbounded RAM buffer flooding
                
    except KeyboardInterrupt:
        print(f"\n[Simulator] Stopped gracefully. Total events: {count}")
        producer.flush()

if __name__ == "__main__":
    main()
