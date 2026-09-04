from inference.features import safe_int, safe_float

def evaluate_rules(event: dict, features: dict) -> list:
    alerts = []
    evt_type = event.get("event_type")

    # 1. DDoS (Volumetric / rejected connection flood)
    if evt_type == "conn":
        orig_pkts = safe_int(event.get("orig_pkts", 0))
        if event.get("conn_state") == "REJ" or orig_pkts > 10000:
            alerts.append({
                "rule_id": "RULE_DDOS_VOLUMETRIC",
                "threat_class": "DDoS",
                "severity": "critical",
                "confidence": 0.95,
                "evidence": {"conn_state": event.get("conn_state"), "orig_pkts": orig_pkts},
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
        # DGA check (Entropy fallback if AI misses)
        entropy = features.get("shannon_entropy", 0.0)
        if entropy > 3.8 and features.get("domain_length", 0) >= 10:
            alerts.append({
                "rule_id": "RULE_DNS_DGA_FALLBACK",
                "threat_class": "DGA / DNS Tunnelling",
                "severity": "medium",
                "confidence": 0.80,
                "evidence": {"shannon_entropy": entropy, "query": query},
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1568.002"
            })

    # 4. Encrypted-Traffic Malware
    if evt_type == "conn":
        ja4 = str(event.get("ja4", "") or "")
        if ja4 and ja4.startswith("t13d"):
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
