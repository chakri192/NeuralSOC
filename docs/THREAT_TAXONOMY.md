# Cyber Threat Taxonomy & Detection Matrix

Mapping of the 6 threat categories NeuralSOC detects to MITRE ATT&CK techniques, the rules/models behind them, and real evidence schemas from the code.

Each category can fire from more than one detector: a fast single-flow rule in `inference/rules.py` (evaluated per-event) and, for several categories, an additional windowed/behavioral rule in `inference/conn_behavior.py` or `inference/dns_behavior.py` (evaluated over a rolling window of related events — see [SECURITY.md](../SECURITY.md) for why both layers exist). The tables below show one representative real `rule_id` and evidence example per category, not an exhaustive list of every rule that can contribute to it.

---

## Threat Matrix Overview

| Code | Threat Category | Primary Detection Technique | MITRE ATT&CK ID | Default Severity |
| :--- | :--- | :--- | :--- | :--- |
| **a** | **Volumetric / Protocol DDoS** | Packet-rate/volume thresholds on TCP SYN floods and rejected-connection floods | **T1498** (Network DoS) | `CRITICAL` |
| **b** | **Botnet C2 Beaconing** | Tiny repeated payloads on non-standard ports; Inter-Arrival Time jitter for windowed beacon detection | **T1071** (App Layer Protocol) / **T1132** (Data Encoding) | `HIGH` |
| **c** | **DGA Domains & DNS Tunnelling** | Hybrid CNN + lexical-feature classifier (`DGA_HybridModel`), entropy fallback rule & long-TXT-record tunnelling check | **T1568.002** (DGA) / **T1071.004** (DNS) | `CRITICAL` / `HIGH` |
| **d** | **Unusual Connections** | Flow autoencoder (reconstruction error vs. a calibrated threshold) — connections that don't fit normal traffic shape | **T1071** (App Layer Protocol, general) | `MEDIUM` |
| **e** | **Reconnaissance & Port Scanning** | Low-packet `S0` (unanswered SYN) connections per source | **T1046** (Network Service Discovery) | `LOW`–`HIGH` |
| **f** | **Data Exfiltration** | Unilateral byte asymmetry — large outbound, negligible inbound | **T1048** (Exfiltration Over Alternative Protocol) | `HIGH` |

---

## Detailed Threat Class Breakdowns

### 1. Volumetric / Protocol DDoS (`RULE_DDOS_VOLUMETRIC`)
- **Vectors Monitored**: a single connection with >10,000 originator packets (critical), or a rejected (`REJ`) connection with ≥100 originator packets (high) — the packet-count gate exists specifically so a single closed port doesn't get flagged as a critical DDoS event.
- **Evidence Output** (`inference/rules.py`):
  ```json
  {
    "rule_id": "RULE_DDOS_VOLUMETRIC",
    "threat_class": "DDoS",
    "severity": "critical",
    "confidence": 0.95,
    "evidence": {"conn_state": "S0", "orig_pkts": 14302},
    "mitre_tactic": "Impact",
    "mitre_technique": "T1498"
  }
  ```

---

### 2. Botnet C2 Beaconing (`RULE_C2_HEARTBEAT`)
- **Vectors Monitored**: tiny (50–150 byte) originator and responder payloads on a port other than 80/443/53 — the fingerprint of a heartbeat-style C2 check-in rather than a real application protocol.
- **Evidence Output** (`inference/rules.py`):
  ```json
  {
    "rule_id": "RULE_C2_HEARTBEAT",
    "threat_class": "C2 Beaconing",
    "severity": "high",
    "confidence": 0.85,
    "evidence": {"orig_bytes": 88, "resp_bytes": 92, "port": 8443},
    "mitre_tactic": "Command and Control",
    "mitre_technique": "T1132"
  }
  ```
- A separate windowed rule (`inference/conn_behavior.py`) tracks inter-arrival-time jitter across repeated connections between the same host pair, for slower beacons a single-flow rule can't see.

---

### 3. DGA Domains & DNS Tunnelling (`DL_CNN_DGA` / `RULE_DNS_TUNNELLING` / `RULE_DNS_DGA_FALLBACK`)
- **Vectors Monitored**:
  - Algorithmically-generated malware domains — scored by the `DGA_HybridModel` CNN (see [docs/MODEL_METHODOLOGY.md](MODEL_METHODOLOGY.md)).
  - DNS tunnelling: any `TXT`-record query with a query string over 60 characters.
  - An entropy fallback for longer domains the model doesn't see confidently.
- **Evidence Output** (`inference/rules.py`, DNS tunnelling rule):
  ```json
  {
    "rule_id": "RULE_DNS_TUNNELLING",
    "threat_class": "DGA / DNS Tunnelling",
    "severity": "high",
    "evidence": {"query_length": 74, "qtype": "TXT"},
    "mitre_tactic": "Command and Control",
    "mitre_technique": "T1071.004"
  }
  ```

---

### 4. Unusual Connections (`DL_AUTOENCODER_FLOW_ANOMALY`)
- **Vectors Monitored**: connections whose shape (byte/packet volume, duration) reconstructs poorly under a `FlowAutoencoder` trained only on real, confirmed-benign CTU-13 traffic — a general anomaly signal for behavior none of the other five, more specific detectors are built to name. Zero payload decryption; scored from NetFlow-style metadata only.
- **Evidence Output** (`inference/stream_processor_faust.py`):
  ```json
  {
    "threat_class": "Anomalous Flow",
    "severity": "medium",
    "rule_id": "DL_AUTOENCODER_FLOW_ANOMALY",
    "evidence": {"reconstruction_mse": 0.0412, "threshold": 0.018}
  }
  ```
- A separate rule, `RULE_TLS_JA4_MALWARE`, also exists for exact-match JA4 TLS fingerprinting against a curated malicious-fingerprint list — but ships with no real threat-intel feed by default and, per real-pcap investigation, **is not deployed in production** (see [docs/MODEL_METHODOLOGY.md](MODEL_METHODOLOGY.md#b-encrypted-session-metadata) and [SECURITY.md](../SECURITY.md)). It is not one of the product's six shipped-by-default detection categories.

---

### 5. Reconnaissance & Port Scanning (`RULE_RECON_PORT_SCAN`)
- **Vectors Monitored**: unanswered SYNs (`conn_state == "S0"`) with fewer than 5 originator packets — a single probe, not a volumetric flood.
- **Evidence Output** (`inference/rules.py`):
  ```json
  {
    "rule_id": "RULE_RECON_PORT_SCAN",
    "threat_class": "Reconnaissance",
    "severity": "low",
    "confidence": 0.75,
    "evidence": {"conn_state": "S0", "target_port": 3389},
    "mitre_tactic": "Discovery",
    "mitre_technique": "T1046"
  }
  ```
- A separate windowed rule (`inference/conn_behavior.py`) tracks fan-out — one source touching many distinct ports or hosts — for slower scans a single connection's fields can't show.

---

### 6. Data Exfiltration (`RULE_CONN_EXFIL`)
- **Vectors Monitored**: outbound transfers over 5MB with under 10KB returned — a large, unilateral byte asymmetry.
- **Evidence Output** (`inference/rules.py`):
  ```json
  {
    "rule_id": "RULE_CONN_EXFIL",
    "threat_class": "Data Exfiltration",
    "severity": "high",
    "confidence": 0.85,
    "evidence": {"orig_bytes": 71827456, "resp_bytes": 140},
    "mitre_tactic": "Exfiltration",
    "mitre_technique": "T1048"
  }
  ```
