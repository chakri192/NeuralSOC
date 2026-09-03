#  Data Diode Cyber Threat Defense Platform

> **Lightweight, Real-Time AI Cyber Threat Detection for Unidirectional IP Traffic (Hardware Data Diode / Passive Monitoring Enclave)**  
> Built for Apple Silicon (ARM64) • Sub-Millisecond Multi-Model Inference • Interactive SOC Defense Dashboard

---

##  Architecture & Data Flow

```
   [ Unidirectional Link / Hardware Data Diode ]
                        │ (Zero Reverse Path - Strictly Read-Only)
                        ▼
       ┌─────────────────────────────────┐
       │     Live Zeek JSON Stream       │  (conn.log, dns.log, ssl.log)
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │   ingest/tail_to_redpanda.py    │  (Non-blocking Inode Tailer)
       └────────────────┬────────────────┘
                        │ Topic: raw_traffic
                        ▼
       ┌─────────────────────────────────┐
       │  Redpanda Broker (ARM64 Docker) │  (512MB RAM, Low-Latency Broker)
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │ inference/stream_processor.py   │  (Multi-Model AI Inference Engine)
       │  • DGA & Tunneling Classifier   │
       │  • Flow Anomaly Isolation Forest│
       │  • Multi-Class Threat Ensemble  │
       │  • Stateful IAT Beacon Tracker  │
       │  • Recon Fan-Out Sweep Tracker  │
       │  • JA3/JA4 Malware Signature DB │
       └────────────────┬────────────────┘
                        │ Topic: security_alerts
                        ▼
       ┌─────────────────────────────────┐
       │ dashboard/app.py (Streamlit)    │  (Live Telemetry, Topology Graph,
       │                                 │   Incident Playbooks, Injector)
       └─────────────────────────────────┘
```

---

##  Key Features & Problem Statement Coverage

| Threat Category | Problem Statement Requirement | Detection Mechanism | MITRE ATT&CK ID |
| :--- | :--- | :--- | :--- |
| **a. Volumetric / Protocol DDoS** | SYN floods, UDP reflection/amplification | Uncompleted TCP `S0` state tracking & UDP amplification port heuristics | **T1498** |
| **b. Botnet C2 Beaconing** | Periodicity & Inter-Arrival Time (IAT) analysis | Sliding window Mean IAT ($\mu$), standard deviation ($\sigma$), and Jitter ($CV < 0.15$) | **T1071** |
| **c. DGA & DNS Tunnelling** | Shannon entropy, query length, record type anomalies | Shannon entropy ($H > 3.8$), Random Forest Classifier, Base64/Hex TXT parsing | **T1568.002** / **T1071.004** |
| **d. Encrypted Malware Sessions** | Metadata-only TLS/QUIC without payload decryption | JA3/JA4 signature database (Cobalt Strike, Sliver, Metasploit), SNI entropy | **T1071.001** / **T1573.002** |
| **e. Reconnaissance & Port Scans** | Fan-out patterns across destination ports or hosts | Stateful tracker identifying Vertical Port Scans and Horizontal Host Sweeps | **T1046** |
| **f. Data Exfiltration** | Asymmetric flow volume and unusual outbound/inbound byte ratios | Outbound-to-inbound asymmetry ratio ($R_{byte} > 500:1$) & Isolation Forest | **T1048** |

---

##  Quality-of-Life (QoL) & Advanced Capabilities

1. ** Interactive Attack Graph & Threat Map**:
   - Visualizes internal compromised hosts connecting to external C2 nodes / drop-sites using interactive Plotly network topology graphs.
2. ** Automated SOC Incident Response Playbooks**:
   - Tailored remediation playbooks with copyable firewall ACL commands (`iptables` / ACLs), forensic checklists, and MITRE mitigation mappings.
3. ** Live Hackathon Demo Attack Injector**:
   - 1-click on-demand attack triggers in the UI allowing judges to inject Cobalt Strike handshakes, DGA storms, 75MB exfiltration bursts, and SYN floods.
4. ** Executive Forensic Incident Report**:
   - One-click generated executive Markdown / CSV incident response audit summaries.
5. ** Real-time Detection Configuration**:
   - Dynamic threshold tuning sliders (Entropy cutoffs, Byte asymmetry ratios, Beaconing jitter tolerances) without restarting workers.

---

##  Performance & Benchmarks (Apple Silicon ARM64)

- **Median Decision Latency (P50)**: **`22.75 µs` (`0.023 ms`)**
- **Sustained Flow Rate**: **`>225 flows/second`** (single-thread worker)
- **Wire Equivalent Bandwidth**: **`17.48 Mbps` sustained metadata telemetry**
- **Memory Footprint**: `< 120 MB RAM`
- **Automated Regression Suite**: `9/9 Tests Passed in 0.184s`

---

##  Live Demo Execution Guide

```bash
# 1. Start Redpanda Broker (Docker)
docker compose up -d

# 2. Start ML Stream Processor (Terminal 1)
venv/bin/python3 inference/stream_processor.py --broker localhost:9092

# 3. Start Zeek Ingestion & Traffic Simulator (Terminal 2)
venv/bin/python3 scripts/simulate_zeek_feed.py --rate 3.0 --burst-attacks &
venv/bin/python3 ingest/tail_to_redpanda.py --broker localhost:9092 --log-dir data/zeek_logs

# 4. Start Enterprise Streamlit SOC Dashboard (Terminal 3)
venv/bin/streamlit run dashboard/app.py

# 5. Start Terminal UI Dashboard (Optional, in a new terminal)
venv/bin/python3 dashboard/cli_dashboard.py
```

Access the live web dashboard at **[http://localhost:8501](http://localhost:8501)**, or use the Terminal UI for a rapid hacker-style operational view.
