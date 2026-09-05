"""
playbooks.py
============
Automated SOC Incident Response Playbooks & Remediation Generator.
Generates containment actions, firewall ACL rules, forensic checklists,
and MITRE ATT&CK mitigation recommendations for detected threats.
"""

from typing import Dict, Any

PLAYBOOK_TEMPLATES = {
    "VOLUMETRIC_PROTOCOL_DDOS": {
        "title": "Volumetric & Protocol DDoS Containment",
        "containment_steps": [
            "Enable upstream BGP Blackhole / Rate-Limiting for victim destination port.",
            "Activate SYN Cookies and aggressive TCP connection timeout parameters on gateway edge.",
            "Block amplification reflector source IPs at border ingress filter.",
        ],
        "firewall_rule": "iptables -A INPUT -p tcp --dport {dst_port} -m limit --limit 25/minute --limit-burst 100 -j ACCEPT",
        "forensic_checklist": [
            "Extract 5-minute PCAP slice around attack onset.",
            "Analyze source IP distribution for spoofed /56 or /64 prefix clusters.",
            "Identify amplification reflection vectors (NTP monlist, DNS ANY, Memcached).",
        ],
        "mitre_mitigations": ["M1037 - Filter Network Traffic", "M1035 - Limit Hardware & Protocol Interfaces"],
    },
    "BOTNET_C2_BEACONING": {
        "title": "Botnet C2 Infrastructure Isolation & Host Triage",
        "containment_steps": [
            "Isolate compromised endpoint from local LAN segment.",
            "Block C2 IP/domain at outbound gateway border router.",
            "Revoke active Kerberos / OAuth sessions associated with the infected host.",
        ],
        "firewall_rule": "iptables -I FORWARD -s {src_ip} -j DROP\niptables -I OUTPUT -d {dst_ip} -j DROP",
        "forensic_checklist": [
            "Acquire volatile memory dump (RAM) of infected endpoint via Volatility / WinPmem.",
            "Inspect process hierarchy for parentless binaries or suspicious PowerShell/rundll32 executions.",
            "Collect scheduled tasks and autorun registry persistence keys.",
        ],
        "mitre_mitigations": ["M1037 - Filter Network Traffic", "M1049 - Antivirus/Antimalware", "M1040 - Network Segmentation"],
    },
    "DGA_DOMAIN": {
        "title": "Algorithmic DGA Resolution Sinkholing",
        "containment_steps": [
            "Add domain to internal DNS sinkhole / RPZ (Response Policy Zone) returning 127.0.0.1.",
            "Identify internal client issuing high-entropy recursive DNS requests.",
            "Trigger automated EDR scan on requesting endpoint.",
        ],
        "firewall_rule": "unbound-control local_zone {domain} always_nxdomain",
        "forensic_checklist": [
            "Extract full DNS query history for requesting source IP over past 24 hours.",
            "Correlate with known DGA seed dates (Conficker, Cryptolocker, Banjori families).",
            "Identify executable responsible for initiating UDP 53 socket connection.",
        ],
        "mitre_mitigations": ["M1031 - Network Intrusion Prevention", "M1020 - Automated Dynamic DNS Filtering"],
    },
    "DNS_TUNNELING_EXFIL": {
        "title": "DNS Tunneling & Data Exfiltration Remediation",
        "containment_steps": [
            "Block authoritative nameserver domain on recursive resolvers.",
            "Enforce strict DNS query length limits (< 60 chars) on perimeter DNS forwarders.",
            "Quarantine endpoint transmitting high-entropy TXT/NULL payloads.",
        ],
        "firewall_rule": "iptables -A FORWARD -s {src_ip} -p udp --dport 53 -m length --length 150:65535 -j DROP",
        "forensic_checklist": [
            "Reconstruct Base64/Hex stream from decoded subdomain chunks.",
            "Perform DLP classification on reconstructed files to assess data exposure.",
            "Analyze process network sockets to find DNS tunneling tools (e.g. dnscat2, iodine).",
        ],
        "mitre_mitigations": ["M1037 - Filter Network Traffic", "M1057 - Data Loss Prevention"],
    },
    "MALICIOUS_JA3_FINGERPRINT": {
        "title": "Encrypted C2 Malware Handshake Interception",
        "containment_steps": [
            "Quarantine infected host immediately via EDR agent.",
            "Blacklist destination C2 IP and JA3 fingerprint across all perimeter sensors.",
            "Scan host for known C2 framework stagers (Cobalt Strike, Sliver, Metasploit).",
        ],
        "firewall_rule": "iptables -I FORWARD -s {src_ip} -d {dst_ip} -j DROP",
        "forensic_checklist": [
            "Extract in-memory DLL injections (e.g. Cobalt Strike Reflective DLL Loader).",
            "Inspect named pipes used for local inter-process communication.",
            "Cross-reference JA3 hash ({ja3_hash}) against latest threat intelligence feeds.",
        ],
        "mitre_mitigations": ["M1037 - Filter Network Traffic", "M1049 - Antivirus/EDR Containment", "M1041 - Execution Prevention"],
    },
    "ENCRYPTED_MALWARE_TLS": {
        "title": "Suspicious TLS Handshake Containment",
        "containment_steps": [
            "Block outbound connections to destination host with anomalous self-signed certificate.",
            "Inspect internal client for unsigned binaries initiating TLS sockets.",
        ],
        "firewall_rule": "iptables -I OUTPUT -d {dst_ip} -p tcp --dport {dst_port} -j DROP",
        "forensic_checklist": [
            "Extract full X.509 certificate metadata from Zeek ssl.log.",
            "Correlate SNI entropy with malware infrastructure hosting providers.",
        ],
        "mitre_mitigations": ["M1037 - Filter Network Traffic", "M1031 - Network Intrusion Prevention"],
    },
    "RECON_PORT_SCAN": {
        "title": "Internal Reconnaissance & Port Scan Containment",
        "containment_steps": [
            "Temporarily restrict source IP from accessing internal server VLANs.",
            "Inspect source host for compromised credentials or scanning tools (Nmap, Masscan).",
            "Verify if target ports contain unpatched vulnerabilities.",
        ],
        "firewall_rule": "iptables -I FORWARD -s {src_ip} -j DROP",
        "forensic_checklist": [
            "Determine whether scan was automated SYN sweep or interactive discovery.",
            "Check authentication logs on target systems for subsequent lateral movement attempts.",
        ],
        "mitre_mitigations": ["M1030 - Network Segmentation", "M1035 - Disable Unnecessary Services"],
    },
    "DATA_EXFILTRATION": {
        "title": "High-Volume Unilateral Data Exfiltration Response",
        "containment_steps": [
            "Sever outbound internet connection for exfiltrating host immediately.",
            "Trigger emergency incident response team notification and forensic preservation.",
            "Block external drop-site / C2 receiver IP across all egress firewalls.",
        ],
        "firewall_rule": "iptables -I FORWARD -s {src_ip} -j REJECT --reject-with icmp-admin-prohibited\niptables -I OUTPUT -d {dst_ip} -j DROP",
        "forensic_checklist": [
            "Audit endpoint file access logs to determine exact sensitive files accessed before exfiltration.",
            "Identify archive tools (7-Zip, WinRAR) or staging directories used prior to upload.",
            "Calculate total exfiltrated data volume across all concurrent connections.",
        ],
        "mitre_mitigations": ["M1057 - Data Loss Prevention", "M1037 - Filter Network Traffic", "M1040 - Restrict File & Directory Access"],
    },
}


import hashlib
import ipaddress
import shlex
import re

THREAT_CLASS_MAP = {
    "DDOS": "VOLUMETRIC_PROTOCOL_DDOS",
    "VOLUMETRIC_PROTOCOL_DDOS": "VOLUMETRIC_PROTOCOL_DDOS",
    "C2 BEACONING": "BOTNET_C2_BEACONING",
    "BOTNET_C2_BEACONING": "BOTNET_C2_BEACONING",
    "DGA / DNS TUNNELLING": "DGA_DOMAIN",
    "DGA": "DGA_DOMAIN",
    "DGA_DOMAIN": "DGA_DOMAIN",
    "DNS TUNNELLING": "DNS_TUNNELING_EXFIL",
    "DNS_TUNNELING_EXFIL": "DNS_TUNNELING_EXFIL",
    "ENCRYPTED-TRAFFIC MALWARE": "ENCRYPTED_MALWARE_TLS",
    "ENCRYPTED_MALWARE_TLS": "ENCRYPTED_MALWARE_TLS",
    "MALICIOUS_JA3_FINGERPRINT": "MALICIOUS_JA3_FINGERPRINT",
    "RECONNAISSANCE": "RECON_PORT_SCAN",
    "RECON_PORT_SCAN": "RECON_PORT_SCAN",
    "DATA EXFILTRATION": "DATA_EXFILTRATION",
    "DATA_EXFILTRATION": "DATA_EXFILTRATION",
}

def enrich_ip_intel(ip_address: str) -> Dict[str, str]:
    """Mock GeoIP and Threat Intelligence Enrichment (Quality of Life Feature)."""
    # A naive string-prefix check ("172.16") previously misclassified most
    # of RFC1918's actual /12 (172.17.x.x-172.31.x.x -- the bulk of the
    # block, and Docker's own default bridge range) as external, while
    # also misclassifying genuinely public 172.160.0.0-172.169.255.255 as
    # internal/trusted. inference/enrichment.py already does this
    # correctly with the ipaddress module -- reuse that logic instead of
    # reimplementing it, incorrectly, a second time.
    if not ip_address:
        return {"country": "Internal / RFC1918", "asn": "N/A", "reputation": "Trusted"}
    try:
        addr = ipaddress.ip_address(ip_address)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return {"country": "Internal / RFC1918", "asn": "N/A", "reputation": "Trusted"}
    except ValueError:
        return {"country": "Internal / RFC1918", "asn": "N/A", "reputation": "Trusted"}

    # Deterministic mock based on hash to keep it consistent
    h = int(hashlib.md5(ip_address.encode(), usedforsecurity=False).hexdigest(), 16)
    countries = ["RU", "CN", "IR", "KP", "BR", "RO", "US", "NL", "DE"]
    asns = ["AS47764", "AS4134", "AS58224", "AS174", "AS398324", "AS20473"]

    country = countries[h % len(countries)]
    asn = asns[(h // 10) % len(asns)]
    rep = "Suspicious (Known Bulletproof Hoster)" if country in ["RU", "CN", "IR", "KP", "RO"] else "Neutral"

    return {"country": country, "asn": asn, "reputation": rep}


def safe_format_string(template_str: str, **kwargs) -> str:
    """Safely format string replacing known placeholders without raising KeyError for unknowns."""
    res = template_str
    for k, v in kwargs.items():
        res = res.replace(f"{{{k}}}", str(v))
    return res


def sanitize_input(val: Any, default: str = "") -> str:
    if val is None:
        return default
    # Strip null bytes and control chars
    clean = re.sub(r'[\r\n\x00]', '', str(val))
    return clean


def generate_playbook(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Generates an actionable incident response playbook tailored to the specific alert."""
    raw_threat_class = alert.get("threat_class") or "DATA_EXFILTRATION"
    normalized_key = THREAT_CLASS_MAP.get(str(raw_threat_class).strip().upper(), "DATA_EXFILTRATION")
    template = PLAYBOOK_TEMPLATES.get(normalized_key, PLAYBOOK_TEMPLATES["DATA_EXFILTRATION"])

    src_ip = sanitize_input(alert.get("source_ip") or alert.get("src_ip") or alert.get("id.orig_h"), "192.168.1.100")
    dst_ip = sanitize_input(alert.get("destination_ip") or alert.get("dst_ip") or alert.get("id.resp_h"), "198.51.100.1")
    dst_port = sanitize_input(alert.get("destination_port") or alert.get("dst_port") or alert.get("id.resp_p"), "443")

    evidence = alert.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    domain = sanitize_input(evidence.get("domain") or evidence.get("query") or alert.get("query"), "malicious-c2.com")
    ja3_hash = sanitize_input(evidence.get("ja3_hash") or evidence.get("ja4"), "a0e9f5d64349fb13191bc781f81f42e1")

    # Threat Intel Enrichment
    dst_intel = enrich_ip_intel(dst_ip)
    src_intel = enrich_ip_intel(src_ip)

    # Sanitize and quote shell arguments to prevent Command Injection in SOAR automation
    quoted_src_ip = shlex.quote(src_ip)
    quoted_dst_ip = shlex.quote(dst_ip)
    quoted_dst_port = shlex.quote(str(dst_port))
    quoted_domain = shlex.quote(domain)
    quoted_ja3 = shlex.quote(ja3_hash)

    formatted_rule = safe_format_string(
        template["firewall_rule"],
        src_ip=quoted_src_ip,
        dst_ip=quoted_dst_ip,
        dst_port=quoted_dst_port,
        domain=quoted_domain,
        ja3_hash=quoted_ja3,
    )

    return {
        "title": template["title"],
        "threat_class": raw_threat_class,
        "severity": alert.get("severity", "HIGH"),
        "containment_steps": template["containment_steps"],
        "recommended_firewall_rule": formatted_rule,
        "forensic_checklist": [
            safe_format_string(item, src_ip=src_ip, dst_ip=dst_ip, domain=domain, ja3_hash=ja3_hash)
            for item in template["forensic_checklist"]
        ],
        "mitre_mitigations": template["mitre_mitigations"],
        "threat_intel": {
            "source": src_intel,
            "destination": dst_intel
        }
    }
