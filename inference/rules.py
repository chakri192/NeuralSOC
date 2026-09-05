from inference.features import safe_int, safe_float

# Known-malicious JA4 fingerprints, matched in FULL (not by prefix -- see
# rule 4 below for why). This repo ships no real threat-intel feed, so the
# only default entry is the exact synthetic value ingest/simulator.py's
# demo attack injector produces, clearly not a real-world signature.
# Populate JA4_MALICIOUS_FINGERPRINTS (comma-separated) with a real,
# curated feed before relying on this in production.
import os as _os
_JA4_MALICIOUS_FINGERPRINTS = frozenset(
    f.strip() for f in _os.getenv(
        "JA4_MALICIOUS_FINGERPRINTS", "t13d000000_rare_fingerprint"
    ).split(",") if f.strip()
)


def evaluate_rules(event: dict, features: dict) -> list:
    alerts = []
    evt_type = event.get("event_type")

    # 1. DDoS (Volumetric / rejected connection flood)
    if evt_type == "conn":
        orig_pkts = safe_int(event.get("orig_pkts", 0))
        conn_state = event.get("conn_state")
        # A single rejected connection (one closed port, one firewall
        # reject) is not volumetric -- this rule previously fired
        # "critical" on `conn_state == "REJ"` alone, regardless of packet
        # count, turning every closed port into a critical DDoS alert.
        # Genuine volume, consistent with this rule's own name, is what
        # gates severity now; a bare low-packet reject is Reconnaissance
        # territory (rule 5 below), not DDoS.
        if orig_pkts > 10000:
            alerts.append({
                "rule_id": "RULE_DDOS_VOLUMETRIC",
                "threat_class": "DDoS",
                "severity": "critical",
                "confidence": 0.95,
                "evidence": {"conn_state": conn_state, "orig_pkts": orig_pkts},
                "mitre_tactic": "Impact",
                "mitre_technique": "T1498"
            })
        elif conn_state == "REJ" and orig_pkts >= 100:
            alerts.append({
                "rule_id": "RULE_DDOS_VOLUMETRIC",
                "threat_class": "DDoS",
                "severity": "high",
                "confidence": 0.85,
                "evidence": {"conn_state": conn_state, "orig_pkts": orig_pkts},
                "mitre_tactic": "Impact",
                "mitre_technique": "T1498"
            })

    # 2. C2 Beaconing
    if evt_type == "conn":
        orig = features.get("orig_bytes", 0)
        resp = features.get("resp_bytes", 0)
        resp_port = safe_int(event.get("id.resp_p", 0))
        # Heartbeat-like tiny repeated payloads on weird ports
        if 50 < orig < 150 and 50 < resp < 150 and resp_port not in [80, 443, 53]:
            alerts.append({
                "rule_id": "RULE_C2_HEARTBEAT",
                "threat_class": "C2 Beaconing",
                "severity": "high",
                "confidence": 0.85,
                "evidence": {"orig_bytes": orig, "resp_bytes": resp, "port": resp_port},
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1132"
            })

    # 3. DGA / DNS Tunnelling
    if evt_type == "dns":
        query = str(event.get("query", ""))
        # Tunneling check
        if len(query) > 60 and event.get("qtype_name") == "TXT":
            alerts.append({
                "rule_id": "RULE_DNS_TUNNELLING",
                "threat_class": "DGA / DNS Tunnelling",
                "severity": "high",
                "confidence": 0.90,
                "evidence": {"query_length": len(query), "qtype": "TXT"},
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071.004"
            })
        # DGA check (Entropy fallback if AI misses). Measured against real
        # traffic: entropy over the whole FQDN (this rule's previous
        # basis) fires on ordinary CDN/cloud cache-busting subdomains --
        # cloudfront.net, sharepoint.com, elb.amazonaws.com, and
        # gravatar.com hashes all scored above 3.8 -- while missing a real
        # DGA sample that scored below it. This fallback exists for
        # longer, tunneling-style domains where entropy is statistically
        # meaningful (an 8-char sample has little room to look "random");
        # short DGA domains are the CNN classifier's job, not this
        # heuristic's. Scoring just the leftmost label, requiring a longer
        # minimum length, and excluding known infrastructure suffixes
        # closes all four measured false positives without needing the
        # length change to also catch what's fundamentally an ML problem.
        label_entropy = features.get("label_entropy", 0.0)
        label_length = features.get("label_length", 0)
        if (
            label_entropy > 3.8
            and label_length >= 16
            and not features.get("is_known_infra_suffix", False)
        ):
            alerts.append({
                "rule_id": "RULE_DNS_DGA_FALLBACK",
                "threat_class": "DGA / DNS Tunnelling",
                "severity": "medium",
                "confidence": 0.80,
                "evidence": {"shannon_entropy": label_entropy, "query": query},
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1568.002"
            })

    # 4. Encrypted-Traffic Malware
    if evt_type == "conn":
        ja4 = str(event.get("ja4", "") or "")
        # "t13d" is the standard JA4 prefix for ANY TLS 1.3 client
        # presenting an SNI -- Chrome, Firefox, curl, effectively all
        # modern HTTPS -- not a malware signature. A JA4 fingerprint's
        # full three segments (version+extensions, cipher-suite hash,
        # extension hash) are what actually identify a specific client
        # implementation; match against a curated set of known-malicious
        # FULL fingerprints, not a 4-character version prefix shared by
        # most of the internet.
        if ja4 and ja4 in _JA4_MALICIOUS_FINGERPRINTS:
            alerts.append({
                "rule_id": "RULE_TLS_JA4_MALWARE",
                "threat_class": "Encrypted-Traffic Malware",
                "severity": "critical",
                "confidence": 0.95,
                "evidence": {"ja4_fingerprint": ja4, "tls_metadata": "Anomalous Cipher Suite"},
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1573"
            })

    # 5. Reconnaissance
    if evt_type == "conn":
        orig_pkts = safe_int(event.get("orig_pkts", 0))
        if event.get("conn_state") == "S0" and orig_pkts < 5:
            alerts.append({
                "rule_id": "RULE_RECON_PORT_SCAN",
                "threat_class": "Reconnaissance",
                "severity": "low",
                "confidence": 0.75,
                "evidence": {"conn_state": "S0", "target_port": event.get("id.resp_p")},
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1046"
            })

    # 6. Data Exfiltration
    if evt_type == "conn":
        resp_bytes = features.get("resp_bytes", 0)
        orig_bytes = features.get("orig_bytes", 0)
        if orig_bytes > 5000000 and resp_bytes < 10000:
            alerts.append({
                "rule_id": "RULE_CONN_EXFIL",
                "threat_class": "Data Exfiltration",
                "severity": "high",
                "confidence": 0.85,
                "evidence": {"orig_bytes": orig_bytes, "resp_bytes": resp_bytes},
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "T1048"
            })

    return alerts
