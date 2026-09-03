#  Model Methodology & Feature Engineering

## 1. Overview
This document details the mathematical formulation, feature engineering pipeline, model architectures, and validation strategy used in the **AI-Based Unidirectional IP Cyber Threat Detection Engine**.

The system operates inside a hardware data diode / passive monitoring enclave under strict constraints:
- **Strictly Read-Only**: Zero feedback or active probing path.
- **Metadata-Only**: No payload decryption (operates exclusively on NetFlow/IPFIX, Zeek logs, TLS/QUIC handshakes, and DNS telemetry).
- **Streaming Execution**: Microsecond-bounded latency per flow event.

---

## 2. Feature Engineering Pipeline

### A. Lexical & Statistical DNS Features ($Threat\ Class\ c$)
For each observed DNS query string $Q$, we compute:
1. **Shannon Entropy**:
   $$H(Q) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Where $P(x_i)$ is the empirical probability of character $x_i$ appearing in the domain body. Algorithmic DGA strings typically exhibit $H(Q) \ge 3.8$, whereas benign natural language domains exhibit $H(Q) \le 2.8$.
2. **Lexical Ratios**:
   - Vowel Ratio: $R_v = \frac{N_{vowels}}{|Q|}$
   - Digit Ratio: $R_d = \frac{N_{digits}}{|Q|}$
   - Consonant Ratio: $R_c = \frac{N_{consonants}}{|Q|}$
   - Unique Character Ratio: $R_u = \frac{|\text{set}(Q)|}{|Q|}$
   - Max Consecutive Consonants: Long unpronounceable consonant clusters (e.g. Conficker).
3. **DNS Tunneling / Exfiltration Encodings**:
   - Detection of hex-encoded ($[0-9a-fA-F]^{16+}$) and Base64-encoded subdomains with deep subdomain levels ($N_{sub} \ge 4$) and anomalous record types (`TXT`, `NULL`).

### B. Encrypted Session Metadata ($Threat\ Class\ d$)
- **JA3 Fingerprinting**: MD5 hash of TLS Client Hello parameters:
  $$\text{JA3} = \text{MD5}(\text{SSLVersion},\ \text{Ciphers},\ \text{SSLExtensions},\ \text{EllipticCurves},\ \text{EllipticCurvePointFormats})$$
  Evaluated against curated C2 signatures (Cobalt Strike, Sliver, Metasploit, TrickBot).
- **SNI Entropy & Certificate Legitimacy**: Entropy of Server Name Indication (SNI) paired with self-signed certificate status.

### C. Flow Dynamics & Velocity Features ($Threat\ Classes\ a, e, f$)
Extracted from connection metadata:
- **Asymmetric Byte Ratio**:
  $$R_{byte} = \frac{\text{Orig\_Bytes}}{\max(1, \text{Resp\_Bytes})}$$
  A critical metric in unidirectional environments. Ratios $>500:1$ with volume $>5\text{MB}$ indicate unilateral exfiltration.
- **Packet & Byte Velocity**:
  $$V_{bytes} = \frac{\text{Orig\_Bytes} + \text{Resp\_Bytes}}{\max(0.001, \text{Duration})}, \quad V_{pkts} = \frac{\text{Orig\_Pkts} + \text{Resp\_Pkts}}{\max(0.001, \text{Duration})}$$
- **Protocol State Flagging**: Half-open TCP states (`S0`, `RSTOS0`, `REJ`) indicating SYN flood or reconnaissance scans.

### D. Inter-Arrival Time (IAT) Periodicity Tracking ($Threat\ Class\ b$)
For sequential flows $(f_1, f_2, \dots, f_k)$ between source IP $S$ and destination IP $D$:
- Inter-Arrival Times: $\Delta t_i = t_i - t_{i-1}$
- Mean IAT: $\mu = \frac{1}{k-1} \sum_{i=2}^{k} \Delta t_i$
- Standard Deviation: $\sigma = \sqrt{\frac{1}{k-1} \sum_{i=2}^{k} (\Delta t_i - \mu)^2}$
- **Coefficient of Variation (Jitter Metric)**:
  $$CV = \frac{\sigma}{\mu}$$
  Low jitter ($CV < 0.15$) with repetitive pulses ($k \ge 4$) indicates automated C2 beacon heartbeats.

---

## 3. Machine Learning Architectures

```
                    ┌──────────────────────────────┐
                    │      Streaming Metadata      │
                    └──────────────┬───────────────┘
                                   │
            ┌──────────────────────┴──────────────────────┐
            ▼                                             ▼
┌───────────────────────┐                     ┌───────────────────────┐
│ Random Forest DGA     │                     │ Isolation Forest      │
│ Classifier            │                     │ Flow Anomaly Model    │
├───────────────────────┤                     ├───────────────────────┤
│ • 50 Decision Trees   │                     │ • 60 Isolation Trees  │
│ • Max Depth: 8        │                     │ • Contamination: 0.03 │
│ • Target: DGA Domains │                     │ • Target: Exfiltration│
│ • Precision: 100%     │                     │ • Fast decision func  │
└───────────────────────┘                     └───────────────────────┘
```

---

## 4. Training & Validation Results

### DGA Random Forest Classifier:
- **Accuracy**: $100.00\%$
- **Validation Dataset**: 380 balanced evaluation samples (Benign Top Alexa vs. Synthetic Conficker/Cryptolocker/Banjori DGAs).
- **Classification Matrix**:
  | Class | Precision | Recall | F1-Score | Support |
  | :--- | :--- | :--- | :--- | :--- |
  | **Benign** | 1.00 | 1.00 | 1.00 | 172 |
  | **DGA** | 1.00 | 1.00 | 1.00 | 208 |

---

## 5. Performance & Throughput Characteristics
Tested on Apple Silicon ARM64:
- **Median Decision Latency (P50)**: **$22.75\ \mu\text{s}$ ($0.023\text{ ms}$)**
- **Sustained Flow Rate**: **$>220\text{ flows/sec}$ (single Python thread)**
- **Memory Footprint**: $< 120\text{ MB RAM}$
