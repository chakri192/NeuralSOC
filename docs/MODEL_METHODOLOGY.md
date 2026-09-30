# Model Methodology & Feature Engineering

## 1. Overview
This document details the feature engineering and model architectures behind NeuralSOC's detection engine.

The system operates inside a hardware data diode / passive monitoring enclave under strict constraints:
- **Strictly Read-Only**: Zero feedback or active probing path.
- **Metadata-Only**: No payload decryption (operates exclusively on NetFlow/IPFIX, Zeek logs, TLS/QUIC handshakes, and DNS telemetry).

---

## 2. Feature Engineering Pipeline

### A. Lexical & Statistical DNS Features
For each observed DNS query string $Q$ (see `inference/models.py`'s `lexical_features`), we compute:
1. **Shannon Entropy**:
   $$H(Q) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Where $P(x_i)$ is the empirical probability of character $x_i$ appearing in the domain body. This feeds both the DGA classifier and a rule-based entropy fallback (`RULE_DNS_DGA_FALLBACK` in `inference/rules.py`), scored on the leftmost label only, with a minimum length and a known-infrastructure-suffix exclusion — added after entropy-over-the-whole-FQDN was measured to false-positive on ordinary CDN/cloud subdomains (cloudfront.net, sharepoint.com, elb.amazonaws.com).
2. **Lexical Ratios**: vowel ratio, digit ratio, consonant ratio, unique-character ratio, longest-consonant-run, hyphen ratio — the independent signal fed into the DGA model's lexical branch (below).
3. **DNS Tunneling / Exfiltration Encodings**: hex-encoded and Base64-encoded subdomains with deep subdomain levels and anomalous record types (`TXT`, `NULL`).

### B. Encrypted-Session Metadata
- **JA4 Fingerprinting** (`inference/rules.py`, `RULE_TLS_JA4_MALWARE`): exact-match against a configurable list of known-malicious JA4 fingerprints (`JA4_MALICIOUS_FINGERPRINTS` env var). This repo ships **no real threat-intel feed** — the only default entry is a synthetic value used by the demo attack injector. Two real-pcap investigations (documented in [SECURITY.md](../SECURITY.md), "JA4 fingerprinting: real data investigated") found that a real malicious JA4 fingerprint is statistically indistinguishable from ordinary Windows/TLS-library networking traffic; the honest conclusion reached there is **no JA4-based rule is deployed by default** in production. The rule exists and is available for a deployment that supplies its own curated, licensed feed.

### C. Flow Dynamics & Velocity Features
Extracted from connection metadata (`inference/conn_behavior.py`, `inference/rules.py`):
- **Asymmetric Byte Ratio**: $R_{byte} = \frac{\text{Orig\_Bytes}}{\max(1, \text{Resp\_Bytes})}$ — ratios $>500{:}1$ with volume in the megabytes indicate unilateral exfiltration (`RULE_DATA_EXFILTRATION`).
- **Packet & Byte Velocity**: bytes and packets per second over a connection's duration.
- **Protocol State Flagging**: half-open TCP states (`S0`, `RSTOS0`, `REJ`) indicating SYN flood or reconnaissance scans.

### D. Inter-Arrival Time (IAT) Periodicity Tracking
For sequential flows between a source and destination:
- Mean IAT $\mu$, standard deviation $\sigma$, and **Coefficient of Variation** $CV = \sigma / \mu$.
- Low jitter ($CV < 0.15$) with repeated pulses indicates an automated C2 beacon heartbeat (`RULE_BOTNET_C2_BEACONING`).

---

## 3. Machine Learning Architectures

Two PyTorch models are trained and shipped (`inference/train_model.py`, weights in `models/`):

```
                    ┌──────────────────────────────┐
                    │      Streaming Metadata      │
                    └──────────────┬───────────────┘
                                   │
            ┌──────────────────────┴──────────────────────┐
            ▼                                             ▼
┌────────────────────────────┐                ┌───────────────────────────┐
│ DGA_HybridModel             │                │ FlowAutoencoder           │
│ (models/cnn_dga.pt)         │                │ (models/autoencoder_flow.pt) │
├────────────────────────────┤                ├───────────────────────────┤
│ • Char embedding (dim 32)   │                │ • 5 → 16 → 8 → 3           │
│ • 3 parallel Conv1d branches│                │   (encoder)               │
│   kernel sizes 3 / 5 / 7,   │                │ • 3 → 8 → 16 → 5           │
│   96 channels each          │                │   (decoder)               │
│ • Adaptive max-pool + concat│                │ • Trained on real CTU-13  │
│ • Parallel lexical-feature  │                │   benign flows only       │
│   branch (16-dim)           │                │ • Anomaly = high recon-   │
│ • FC(320→128) → FC(128→1)   │                │   struction MSE vs. a     │
│ • Sigmoid output             │                │   calibrated threshold    │
│ • Target: DGA domain vs.    │                │ • Target: connections     │
│   benign                    │                │   that don't fit normal   │
│                              │                │   traffic shape           │
└────────────────────────────┘                └───────────────────────────┘
```

The DGA model's three parallel convolution branches (rather than one) let it capture word-fragment-scale patterns as well as short n-grams — added after a single-branch CNN measured only 38.1% recall against a real held-out DGA benchmark and missed most real dictionary-style domains (e.g. from a Lumma Stealer capture) that are deliberately built from real words to defeat character-pattern classifiers alone. A bidirectional-LSTM branch was also investigated and reverted after failing to clear regression gates on both real validation datasets simultaneously — a genuine, disclosed negative result, written up in full in [docs/DGA_MODEL_ROADMAP.md](DGA_MODEL_ROADMAP.md).

---

## 4. Training & Validation Results

Both models are validated against real captured/published traffic, not synthetic-only benchmarks — full methodology, datasets, and every negative result along the way are in [SECURITY.md](../SECURITY.md#model-validation-against-real-world-data). Current committed baselines:

| Model | Precision | Recall | False positives | Dataset |
| :--- | :--- | :--- | :--- | :--- |
| DGA `DGA_HybridModel` | 84.6% | 77.2% | 13.9% | Real domains (Cucchiarelli et al. 2021) — `benchmarks/dga_family_recall_baseline.json` |
| Flow `FlowAutoencoder` | 95.8% | 54.5% | 0.63% | Real botnet captures, CTU-13, all 12 non-held-out scenarios — `benchmarks/flow_autoencoder_all_scenarios_baseline.json` |
| Combined incident score | 98.3% | 53.0% | 1.15% | `benchmarks/composite_scoring_baseline.json` |

These numbers are re-derived directly from the committed JSON files above, not hand-copied — a stale or rounded-off figure here would drift from those files and be easy to catch by diffing against them.

---

## 5. Performance

A throughput/latency micro-benchmark exists at `scripts/benchmark_throughput.py`. No specific latency or flows/sec figure is committed as a baseline here — run the script against your own hardware rather than relying on a number this document can't currently trace to a checked-in result.
