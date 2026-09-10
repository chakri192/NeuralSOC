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

### 1. Dictionary DGA & DNS Tunnelling (Deep Learning)
* **Threat:** Hackers exfiltrate data or find C2 servers using randomized domain names.
* **Solution:** We trained a **PyTorch 1D Convolutional Neural Network (CNN)**. Instead of just looking at entropy, the CNN reads the sequence of characters to catch advanced "Dictionary DGAs" that trick traditional ML algorithms.

### 2. Zero-Day Data Exfiltration (Statistical rule live today; Deep Learning trained, not yet wired in)
* **Threat:** A compromised insider machine starts uploading a database to an unknown IP.
* **What's live:** A rule flags any connection sending more than 5MB out while receiving less than 10KB back — an asymmetric, one-directional transfer.
* **What's built for the next iteration:** A PyTorch Deep Autoencoder, trained purely on benign traffic to learn what "normal" looks like, so a flow it fails to reconstruct well (a high Mean Squared Error) would flag as anomalous. It exists and trains successfully but the live stream processor doesn't call it yet — an honest gap, not a hidden one.

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
