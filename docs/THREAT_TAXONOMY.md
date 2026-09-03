#  Cyber Threat Taxonomy & Detection Matrix

Comprehensive mapping of all 6 threat categories specified in the Problem Statement to MITRE ATT&CK techniques, detection algorithms, and evidence schemas.

---

##  Threat Matrix Overview

| Code | Threat Category | Primary Detection Technique | MITRE ATT&CK ID | Default Severity |
| :--- | :--- | :--- | :--- | :--- |
| **a** | **Volumetric / Protocol DDoS** | SYN flood rate & UDP amplification port tracking | **T1498** (Network DoS) | `CRITICAL` |
| **b** | **Botnet C2 Beaconing** | Inter-Arrival Time (IAT) periodicity & Jitter CV ($CV < 0.15$) | **T1071** (App Layer Protocol) | `HIGH` |
| **c** | **DGA Domains & DNS Tunnelling** | Shannon Entropy ($H > 3.8$), Random Forest ML & Hex/Base64 TXT parsing | **T1568.002** (DGA) / **T1071.004** (DNS) | `CRITICAL` / `HIGH` |
| **d** | **Encrypted Malware Sessions** | JA3/JA4 TLS fingerprinting, SNI entropy & self-signed certificates | **T1071.001** (Web Protocols) / **T1573.002** (Asymmetric Crypt) | `CRITICAL` |
| **e** | **Reconnaissance & Port Scanning** | Stateful sliding window fan-out tracker (Horizontal sweeps & vertical scans) | **T1046** (Network Service Discovery) | `HIGH` |
| **f** | **Data Exfiltration** | Unilateral byte asymmetry ratios ($R > 500:1$) & Isolation Forest | **T1048** (Exfiltration Over Protocol) | `CRITICAL` |

---

##  Detailed Threat Class Breakdowns

### 1. Volumetric / Protocol DDoS (`VOLUMETRIC_PROTOCOL_DDOS`)
- **Vectors Monitored**:
  - TCP SYN Floods (`conn_state`: `S0` or `RSTOS0` with high packet rates).
  - UDP Protocol Amplification: NTP (port 123), DNS (port 53), Memcached (port 11211), SSDP (port 1900), SNMP (port 161).
- **Evidence Output**:
  ```json
  {
    "reason": "High-rate uncompleted TCP SYN flood (350 packets, state=S0)",
    "subclass": "TCP_SYN_FLOOD",
    "packets_per_sec": 3500.0,
    "proto": "tcp",
    "conn_state": "S0"
  }
  ```

---

### 2. Botnet C2 Beaconing (`BOTNET_C2_BEACONING`)
- **Vectors Monitored**:
  - Low-jitter recurring connection heartbeats to command & control nodes.
- **Evidence Output**:
  ```json
  {
    "reason": "Periodic C2 Heartbeat: Interval ~10.0s (Jitter CV=0.012)",
    "mean_interval_sec": 10.0,
    "jitter_cv": 0.012,
    "observed_pulses": 6,
    "recent_iats": [10.0, 10.0, 9.98, 10.01, 10.0]
  }
  ```

---

### 3. DGA Domains & DNS Tunnelling (`DGA_DOMAIN` / `DNS_TUNNELING_EXFIL`)
- **Vectors Monitored**:
  - Algorithmic malware domain lookups (Conficker, Cryptolocker, Banjori).
  - Encoded data exfiltration via deep subdomains or TXT/NULL record queries.
- **Evidence Output**:
  ```json
  {
    "reason": "High-Entropy Long Subdomain Payload (58 chars, H=3.92)",
    "query": "exfil.01af89e2bcd3456789abcdef012345.tunnel-c2.net",
    "query_length": 58,
    "entropy": 3.92,
    "qtype": "TXT",
    "subdomain_levels": 3
  }
  ```

---

### 4. Encrypted Malware Sessions (`MALICIOUS_JA3_FINGERPRINT` / `ENCRYPTED_MALWARE_TLS`)
- **Vectors Monitored**:
  - Zero payload decryption.
  - Client Hello JA3 signatures for Cobalt Strike, Sliver C2, Metasploit Meterpreter, TrickBot, AsyncRAT, QakBot.
- **Evidence Output**:
  ```json
  {
    "reason": "Known Malware / C2 Fingerprint: Cobalt Strike Beacon",
    "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
    "malware_family": "Cobalt Strike Beacon",
    "threat_description": "Default Cobalt Strike Malleable C2 HTTPS Profile",
    "sni": "cdn-cloud-update-service.com"
  }
  ```

---

### 5. Reconnaissance & Port Scanning (`RECON_PORT_SCAN`)
- **Vectors Monitored**:
  - Vertical Port Scans: Single source scanning $\ge 12$ distinct ports on a single host.
  - Horizontal Host Sweeps: Single source sweeping a common service port across many subnet hosts.
- **Evidence Output**:
  ```json
  {
    "reason": "Active Reconnaissance: Vertical Port Scan",
    "scan_type": "VERTICAL_PORT_SCAN",
    "target": "192.168.1.50",
    "unique_probes": 15,
    "details": {
      "sample_ports": [21, 22, 23, 25, 80, 443, 445, 3389]
    }
  }
  ```

---

### 6. Data Exfiltration (`DATA_EXFILTRATION` / `FLOW_ANOMALY`)
- **Vectors Monitored**:
  - Massive unilateral outbound byte transfers with negligible response volume ($R_{byte} > 500:1$).
  - Outlier flow velocities flagged by Isolation Forest.
- **Evidence Output**:
  ```json
  {
    "reason": "Massive Unidirectional Outbound Transfer: 68.5 MB sent, 140 bytes received (Asymmetry: 489285:1)",
    "orig_bytes": 71827456,
    "resp_bytes": 140,
    "byte_asymmetry_ratio": 489285.0,
    "duration_sec": 4.8
  }
  ```
