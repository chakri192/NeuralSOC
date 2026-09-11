# AI-Powered Cyber Threat Detection Enclave

##  The Problem Statement
In highly secure environments (like nuclear power plants, financial mainframes, or intelligence databases), you cannot put traditional inline firewalls because an attacker could hack the firewall to breach the network. Instead, security teams use **Hardware Data Diodes**—physical devices that only allow data to flow *out*, never in. 

**The Challenge:** How do we detect advanced cyber attacks (like Zero-Days, Botnets, and Exfiltration) in real-time when we are completely blind to the payload (due to encryption) and can only passively listen to a unidirectional stream of network metadata?

##  Architecture & Tech Stack
This project simulates a real-time, high-speed SOC (Security Operations Center) data pipeline:
1. **Sensor:** Zeek Network Security Monitor logs.
2. **Message Broker:** Redpanda (a high-performance C++ Kafka alternative) buffers the streaming logs.
3. **AI Inference Engine:** A custom Python stream processor evaluates packets in under 1 millisecond.
4. **Triage Dashboard:** An ultra-minimalist Streamlit Web UI for security analysts.

##  The AI & Detection Engines
To solve the payload-blindness constraint, the system uses a hybrid mix of **Deep Learning, Machine Learning, and Behavioral Statistics** to detect the 6 deadliest threat vectors:

### 1. DGA & DNS Tunnelling (Deep Learning, validated against real malware)
* **Threat:** Hackers exfiltrate data or find C2 servers using randomized domain names — or real-word domains built to look legitimate.
* **Solution:** A **PyTorch hybrid model** — three parallel 1D-CNN branches (kernel sizes 3/5/7) reading the character sequence at multiple scales, plus a lexical-statistics branch (entropy, digit/vowel ratio, etc.) as a second, independent signal — specifically built to catch dictionary-style DGA that a pure character CNN misses.
* **Validated against real data, not just our own simulator:** run against a published research dataset of 25 real malware families' actual DGA domains — 84.6% precision, 77.2% recall, 13.9% false-positive rate, up from 38.1% recall in the original model with every single family at or above its starting point (a per-family regression gate checks this on every run, not just the aggregate number). Also run against a real published Lumma Stealer pcap end-to-end through the live pipeline: catches most of the genuinely suspicious domains in that capture (was 1 of 7 before this work). Honest nuance if asked: false-positive rate did rise (5.9% → 13.9%) for the recall gain — a real, disclosed cost, not a hidden one.

### 2. Zero-Day Data Exfiltration & Behavioral Anomalies (Statistical rule + Deep Learning, both live)
* **Threat:** A compromised insider machine starts uploading a database to an unknown IP -- or any flow that simply doesn't look like the rest of the traffic on this network.
* **The rule:** Flags any connection sending more than 5MB out while receiving less than 10KB back — an asymmetric, one-directional transfer.
* **The model:** A PyTorch Deep Autoencoder trained on a 50/50 mix of real botnet-traffic-dataset benign flows and synthetic traffic, learning what "normal" looks like (bytes, duration, packet count), flags any flow it reconstructs badly (Mean Squared Error above a real-data-calibrated threshold). Runs on every connection event alongside the rule, in the same bounded inference pool as the DGA CNN. The two catch different things: the rule needs the specific "big upload, tiny reply" shape; the autoencoder catches anything behaviorally unusual, rule or no rule. **Validated against real data:** a real, held-out botnet-traffic dataset (CTU-13) measures 100% precision, 99.8% recall, 0.00% false-positive rate — up from a ~98% false-positive rate when this model was trained on synthetic data alone, the same real-world-validation discipline applied to the DGA classifier below.

### 3. Botnet C2 Beaconing (Statistical detection)
* **Threat:** Malware quietly "calls home" to a hacker's command server every few minutes.
* **Solution:** A rule flags tiny, near-identical payload sizes (50-150 bytes) repeating in both directions on a port that isn't standard web/DNS traffic (80, 443, 53) — the shape of an automated heartbeat, not a person browsing.

### 4. Malware in Encrypted Sessions (Cryptographic Fingerprinting)
* **Threat:** We cannot decrypt the traffic because of the Data Diode.
* **Solution:** We extract the **JA4 fingerprint** (the modern successor to JA3) from the initial TLS handshake — the full fingerprint, not just its version prefix, which nearly all modern HTTPS traffic shares — and match it against a curated list of known-malicious client fingerprints, without ever decrypting the payload. The shipped list ships with one synthetic demo entry; a real deployment needs a real threat-intel feed behind it.

### 5. Reconnaissance & Port Scanning
* **Threat:** An infected IoT device sweeps the internal network for open ports.
* **Solution:** Each individual connection attempt that never completes (a handshake with under 5 packets) is flagged on its own. The real "tracking" happens one layer up: the correlation engine's 300-second sliding window groups repeated detections from the same source into a single escalated incident instead of flooding an analyst with dozens of separate low-severity alerts. If asked for a per-target/per-port fan-out calculation specifically — that doesn't exist yet; the grouping is by source and time window, not by which ports were touched.

### 6. Volumetric Protocol DDoS
* **Threat:** A massive SYN Flood or UDP Reflection attack designed to take down services.
* **Solution:** A single connection with an unusually high packet count (or a rejected connection with a meaningful packet count behind it) is flagged directly — a threshold check, not a rate-of-change or packet-per-second velocity calculation. Sustained floods get grouped into one incident by the same correlation window described above.

##  Key "Wow" Factors for the Demo
* **Lightweight Edge-AI:** The compiled `.pt` model file(s) weigh a few megabytes, not gigabytes. Requires zero GPUs and runs entirely on CPU.
* **Fast Inference:** No LLM anywhere in the detection path — a small, targeted CNN plus straightforward statistical rules, not a heavyweight model, score each event.
* **Enterprise Minimalist UI:** Built for real SOC analysts. No massive JSON dumps or bloated configurations — just clean critical telemetry.
* **Real multi-tenant accounts, live:** Not a single shared login — real per-employee accounts, an admin page to invite teammates and mint sensor tokens, and a live audit log of every login/invite/triage action, all demoable today.

<!-- Cut two claims here that don't hold up: "Scikit-Learn forests" (scikit-learn is a listed dependency but is never actually imported by any detection code — grep confirms it) and "Live Cloudflare Tunneling" (no cloudflared integration exists anywhere in this repo; "cloudflare.com" only ever appears as an example benign domain name in test/simulator data). Don't claim either live if asked. -->
