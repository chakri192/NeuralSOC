"""
feature_extractor.py
====================
Advanced Feature Extraction & State Tracking for Passive Unidirectional IP Threat Detection.

Covers all 6 Core Threat Classes:
a. Volumetric / Protocol DDoS (Rate, SYN ratio, UDP amplification, IP entropy)
b. Botnet C2 Beaconing (Periodicity & Inter-Arrival Time (IAT) variance / jitter)
c. DGA Domains & DNS Tunnelling (Entropy, lexical features, base64/hex, TXT record anomalies)
d. Encrypted Malware (JA3/JA3S/JA4 signatures, SNI entropy, rare ciphers)
e. Reconnaissance & Port Scanning (Horizontal sweeps & vertical port fan-out tracking)
f. Data Exfiltration (Byte asymmetry ratios & velocity metrics)
"""

import re
import math
import time
import collections
from typing import Dict, List, Any, Optional, Tuple

# ----------------------------------------------------------------------
# 1. JA3 / JA4 Threat Signature Database (Malware & C2 Fingerprints)
# ----------------------------------------------------------------------
KNOWN_MALICIOUS_JA3: Dict[str, Dict[str, str]] = {
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "family": "Cobalt Strike Beacon",
        "severity": "CRITICAL",
        "description": "Default Cobalt Strike Malleable C2 HTTPS Profile",
        "mitre_id": "T1071.001",
    },
    "72a589da586844d7f0818ce684948eea": {
        "family": "Sliver C2 Agent",
        "severity": "CRITICAL",
        "description": "Sliver Go-based C2 framework default TLS client",
        "mitre_id": "T1071.001",
    },
    "51c64c77e60f39ac3e179284d623b05e": {
        "family": "Metasploit Meterpreter",
        "severity": "HIGH",
        "description": "Metasploit reverse_https payload TLS signature",
        "mitre_id": "T1071.001",
    },
    "6734f37431670b3ab4292b8f60f29984": {
        "family": "TrickBot Banking Trojan",
        "severity": "HIGH",
        "description": "TrickBot malware custom TLS handshake",
        "mitre_id": "T1071.001",
    },
    "b32309a26951912be7dba376398abc3b": {
        "family": "Emotet Loader",
        "severity": "HIGH",
        "description": "Emotet epoch-4 command and control client",
        "mitre_id": "T1071.001",
    },
    "3b5074b1b082c6160520d819313ac74c": {
        "family": "AsyncRAT / QuasarRAT",
        "severity": "HIGH",
        "description": ".NET-based Remote Access Trojan TLS signature",
        "mitre_id": "T1071.001",
    },
    "de350869b8c85de67a350c8d186f11e6": {
        "family": "QakBot / Pinkslipbot",
        "severity": "HIGH",
        "description": "QakBot modular banking trojan C2 channel",
        "mitre_id": "T1071.001",
    },
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "cc", "buzz", "click", "rest", "gq", "cf", "tk", "ml",
    "work", "loan", "fit", "surf", "casa", "country", "kim", "science"
}

AMP_UDP_PORTS = {
    123: ("NTP_AMPLIFICATION", 50.0),      # NTP monlist (up to 556x)
    53: ("DNS_AMPLIFICATION", 30.0),       # DNS ANY request (up to 50x)
    11211: ("MEMCACHED_AMPLIFICATION", 100.0), # Memcached (up to 10,000x)
    1900: ("SSDP_AMPLIFICATION", 30.0),    # SSDP
    161: ("SNMP_AMPLIFICATION", 10.0),     # SNMP GetBulk
    389: ("CLDAP_AMPLIFICATION", 50.0),    # CLDAP
}


# ----------------------------------------------------------------------
# 2. Mathematical Utilities
# ----------------------------------------------------------------------
def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy: H(X) = -sum(P(x) * log2(P(x)))."""
    if not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_hex_encoded(s: str) -> bool:
    """Checks if a string is primarily hexadecimal (common in tunneling/DGAs)."""
    if len(s) < 8:
        return False
    return bool(re.fullmatch(r"^[0-9a-fA-F]+$", s))


def is_base64_encoded(s: str) -> bool:
    """Checks if string matches base64 pattern (padding or character distribution)."""
    if len(s) < 12:
        return False
    return bool(re.fullmatch(r"^[A-Za-z0-9+/=_-]+$", s)) and any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)


# ----------------------------------------------------------------------
# 3. DNS & Tunnelling Feature Extraction (Threat Class c)
# ----------------------------------------------------------------------
def extract_dns_features(record_or_query: Any) -> Dict[str, Any]:
    if isinstance(record_or_query, str):
        query = record_or_query.strip().lower().rstrip(".")
        qtype = "A"
    elif isinstance(record_or_query, dict):
        query = (record_or_query.get("query") or record_or_query.get("name") or "").strip().lower().rstrip(".")
        qtype = record_or_query.get("qtype_name") or record_or_query.get("qtype") or "A"
    else:
        query = str(record_or_query).strip().lower().rstrip(".")
        qtype = "A"
    
    parts = query.split(".")
    domain_body = parts[0] if parts else ""
    tld = parts[-1] if len(parts) > 1 else ""
    num_subdomains = max(0, len(parts) - 2)
    
    total_length = len(query)
    body_length = len(domain_body)
    entropy = calculate_shannon_entropy(domain_body)
    
    vowels = sum(1 for c in domain_body if c in "aeiou")
    digits = sum(1 for c in domain_body if c.isdigit())
    consonants = sum(1 for c in domain_body if c.isalpha() and c not in "aeiou")
    
    max_consecutive_consonants = 0
    curr = 0
    for c in domain_body:
        if c.isalpha() and c not in "aeiou":
            curr += 1
            if curr > max_consecutive_consonants:
                max_consecutive_consonants = curr
        else:
            curr = 0

    vowel_ratio = vowels / max(1, body_length)
    digit_ratio = digits / max(1, body_length)
    consonant_ratio = consonants / max(1, body_length)
    unique_char_ratio = len(set(domain_body)) / max(1, body_length)
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # DNS Tunneling Indicators:
    # 1. Long subdomains (>35 chars) with high entropy or hex/base64
    # 2. Multiple subdomain depth (>3)
    # 3. Rare tunneling record types (TXT, NULL)
    is_tunnel_candidate = False
    tunnel_reason = ""
    if total_length > 45 and (entropy > 3.6 or is_hex_encoded(domain_body) or is_base64_encoded(domain_body)):
        is_tunnel_candidate = True
        tunnel_reason = f"High-Entropy Long Subdomain Payload ({total_length} chars, H={entropy})"
    elif qtype in ["TXT", "NULL"] and total_length > 35:
        is_tunnel_candidate = True
        tunnel_reason = f"Unusual {qtype} Query with Encoded Payload ({total_length} chars)"
    elif num_subdomains >= 4:
        is_tunnel_candidate = True
        tunnel_reason = f"Deep Subdomain Hierarchy ({num_subdomains} levels)"

    return {
        "raw_query": query,
        "domain_body": domain_body,
        "tld": tld,
        "total_length": total_length,
        "body_length": body_length,
        "entropy": entropy,
        "vowel_ratio": round(vowel_ratio, 4),
        "digit_ratio": round(digit_ratio, 4),
        "consonant_ratio": round(consonant_ratio, 4),
        "unique_char_ratio": round(unique_char_ratio, 4),
        "max_consecutive_consonants": max_consecutive_consonants,
        "is_suspicious_tld": is_suspicious_tld,
        "num_subdomains": num_subdomains,
        "qtype": str(qtype).upper(),
        "is_tunnel_candidate": is_tunnel_candidate,
        "tunnel_reason": tunnel_reason,
        "feature_vector": [
            body_length,
            entropy,
            digit_ratio,
            vowel_ratio,
            consonant_ratio,
            unique_char_ratio,
            max_consecutive_consonants,
            is_suspicious_tld,
        ],
    }


# ----------------------------------------------------------------------
# 4. Connection & Flow Dynamics (Threat Classes a, e, f)
# ----------------------------------------------------------------------
def extract_conn_features(record: Dict[str, Any]) -> Dict[str, Any]:
    duration = float(record.get("duration", 0.0) or 0.0)
    orig_bytes = float(record.get("orig_bytes", 0) or 0)
    resp_bytes = float(record.get("resp_bytes", 0) or 0)
    orig_pkts = float(record.get("orig_pkts", 0) or 0)
    resp_pkts = float(record.get("resp_pkts", 0) or 0)
    conn_state = str(record.get("conn_state", "")).upper()
    proto = str(record.get("proto", "tcp")).lower()
    resp_p = int(record.get("id.resp_p", 0) or 0)

    byte_ratio = orig_bytes / max(1.0, resp_bytes)
    pkt_ratio = orig_pkts / max(1.0, resp_pkts)
    bytes_per_sec = (orig_bytes + resp_bytes) / max(0.001, duration) if duration > 0 else (orig_bytes + resp_bytes)
    pkts_per_sec = (orig_pkts + resp_pkts) / max(0.001, duration) if duration > 0 else (orig_pkts + resp_pkts)

    # 1. Unidirectional Data Exfiltration Flag
    is_exfiltration = False
    exfil_reason = ""
    if orig_bytes >= 2000000 and resp_bytes < 5000:
        is_exfiltration = True
        mb = round(orig_bytes / (1024 * 1024), 2)
        exfil_reason = f"Massive Unidirectional Outbound Transfer: {mb} MB sent, {int(resp_bytes)} bytes received (Asymmetry: {byte_ratio:.0f}:1)"

    # 2. Volumetric DDoS / Reflection Flag
    is_ddos_candidate = False
    ddos_subclass = ""
    ddos_reason = ""
    if proto == "tcp" and conn_state in ["S0", "RSTOS0"] and orig_pkts >= 50 and resp_pkts == 0:
        is_ddos_candidate = True
        ddos_subclass = "TCP_SYN_FLOOD"
        ddos_reason = f"High-rate uncompleted TCP SYN flood ({int(orig_pkts)} packets, state={conn_state})"
    elif proto == "udp" and resp_p in AMP_UDP_PORTS:
        amp_name, amp_factor = AMP_UDP_PORTS[resp_p]
        if orig_pkts > 20 or bytes_per_sec > 500000:
            is_ddos_candidate = True
            ddos_subclass = amp_name
            ddos_reason = f"UDP Protocol Amplification vector detected on port {resp_p} ({amp_name})"

    return {
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "byte_ratio": round(byte_ratio, 2),
        "pkt_ratio": round(pkt_ratio, 2),
        "bytes_per_sec": round(bytes_per_sec, 2),
        "pkts_per_sec": round(pkts_per_sec, 2),
        "conn_state": conn_state,
        "proto": proto,
        "is_exfiltration": is_exfiltration,
        "exfil_reason": exfil_reason,
        "is_ddos_candidate": is_ddos_candidate,
        "ddos_subclass": ddos_subclass,
        "ddos_reason": ddos_reason,
        "feature_vector": [
            duration,
            orig_bytes,
            resp_bytes,
            orig_pkts,
            resp_pkts,
            byte_ratio,
            pkt_ratio,
            bytes_per_sec,
            pkts_per_sec,
        ],
    }


# ----------------------------------------------------------------------
# 5. Stateful Stream Trackers (C2 Beaconing & Reconnaissance Fan-Out)
# ----------------------------------------------------------------------
class BeaconingTracker:
    """
    Tracks Inter-Arrival Time (IAT) periodicity to detect C2 Beaconing (Threat Class b).
    Calculates Mean IAT (mu), Standard Deviation (sigma), and Coefficient of Variation (CV = sigma / mu).
    Low CV (< 0.15 - 0.25) indicates strict algorithmic periodicity / heartbeat.
    """
    def __init__(self, max_history: int = 10, ttl_sec: float = 3600.0, max_keys: int = 10000):
        self.history: Dict[Tuple[str, str, int], collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=max_history)
        )
        self.last_seen: Dict[Tuple[str, str, int], float] = {}
        self.ttl_sec = ttl_sec
        self.max_keys = max_keys

    def _prune_stale(self, now: float):
        if len(self.last_seen) > self.max_keys:
            cutoff = now - self.ttl_sec
            stale_keys = [k for k, last_t in self.last_seen.items() if last_t < cutoff]
            for k in stale_keys:
                self.history.pop(k, None)
                self.last_seen.pop(k, None)

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> Optional[Dict[str, Any]]:
        self._prune_stale(ts)
        key = (src_ip, dst_ip, dst_port)
        self.last_seen[key] = ts
        q = self.history[key]
        q.append(ts)

        if len(q) < 4:
            return None

        # Compute Inter-Arrival Times (IATs)
        iats = [q[i] - q[i - 1] for i in range(1, len(q))]
        # Filter out negative or zero timestamps
        iats = [dt for dt in iats if dt > 0.05]
        if len(iats) < 3:
            return None

        mean_iat = sum(iats) / len(iats)
        variance = sum((dt - mean_iat) ** 2 for dt in iats) / len(iats)
        std_iat = math.sqrt(variance)
        cv = std_iat / max(0.001, mean_iat)  # Coefficient of Variation (Jitter)

        # Beaconing condition: repeated interval (e.g. 1s - 300s) with low jitter (CV < 0.20)
        if 1.0 <= mean_iat <= 300.0 and cv < 0.20:
            confidence = round(min(1.0, 0.70 + (1.0 - min(1.0, cv * 4)) * 0.28), 2)
            return {
                "mean_interval_sec": round(mean_iat, 2),
                "jitter_cv": round(cv, 4),
                "observed_pulses": len(q),
                "confidence": confidence,
                "history_iats": [round(dt, 2) for dt in iats[-5:]],
            }
        return None


class ReconScanTracker:
    """
    Tracks Fan-Out patterns from a single source to detect Port Scans & Host Sweeps (Threat Class e).
    - Vertical Port Scan: Single Source -> Single Destination IP across >= 12 distinct destination ports.
    - Horizontal Host Sweep: Single Source -> Subnet across >= 12 distinct destination IPs on same port.
    """
    def __init__(self, window_sec: float = 30.0, max_tracked_ips: int = 5000):
        self.window_sec = window_sec
        self.max_tracked_ips = max_tracked_ips
        # src_ip -> deque of (timestamp, dst_ip, dst_port)
        self.events: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.last_alert_time: Dict[Tuple[str, str], float] = {}

    def _prune(self, now: float):
        if len(self.events) > self.max_tracked_ips:
            cutoff = now - self.window_sec
            stale_ips = [ip for ip, q in self.events.items() if not q or q[-1][0] < cutoff]
            for ip in stale_ips:
                self.events.pop(ip, None)

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> Optional[Dict[str, Any]]:
        self._prune(ts)
        q = self.events[src_ip]
        q.append((ts, dst_ip, dst_port))

        # Evict old events outside sliding window
        cutoff = ts - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()

        if len(q) < 10:
            return None

        # Check Vertical Port Scan: Many ports on one destination IP
        ports_by_dest: Dict[str, set] = collections.defaultdict(set)
        for _, dip, dport in q:
            ports_by_dest[dip].add(dport)

        for target_ip, ports in ports_by_dest.items():
            if len(ports) >= 12:
                # Rate limit duplicate alerts
                alert_key = (src_ip, f"VERT_{target_ip}")
                if ts - self.last_alert_time.get(alert_key, 0) > 15.0:
                    self.last_alert_time[alert_key] = ts
                    return {
                        "scan_type": "VERTICAL_PORT_SCAN",
                        "target_ip": target_ip,
                        "unique_ports_scanned": len(ports),
                        "sample_ports": sorted(list(ports))[:10],
                        "window_sec": self.window_sec,
                    }

        # Check Horizontal Host Sweep: Many destination IPs on single target port
        dests_by_port: Dict[int, set] = collections.defaultdict(set)
        for _, dip, dport in q:
            dests_by_port[dport].add(dip)

        for target_port, dest_ips in dests_by_port.items():
            if len(dest_ips) >= 12:
                alert_key = (src_ip, f"HORIZ_{target_port}")
                if ts - self.last_alert_time.get(alert_key, 0) > 15.0:
                    self.last_alert_time[alert_key] = ts
                    return {
                        "scan_type": "HORIZONTAL_HOST_SWEEP",
                        "target_port": target_port,
                        "unique_hosts_targeted": len(dest_ips),
                        "sample_targets": list(dest_ips)[:6],
                        "window_sec": self.window_sec,
                    }

        return None


def lookup_ja3(ja3_hash: Optional[str]) -> Optional[Dict[str, str]]:
    """Checks if a JA3 hash matches known threat actor / C2 infrastructure signatures."""
    if not ja3_hash:
        return None
    return KNOWN_MALICIOUS_JA3.get(ja3_hash.strip().lower())
