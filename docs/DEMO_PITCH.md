# AI-Powered Cyber Threat Detection Enclave

## 🎯 The Problem Statement
In highly secure environments (like nuclear power plants, financial mainframes, or intelligence databases), you cannot put traditional inline firewalls because an attacker could hack the firewall to breach the network. Instead, security teams use **Hardware Data Diodes**—physical devices that only allow data to flow *out*, never in. 

**The Challenge:** How do we detect advanced cyber attacks (like Zero-Days, Botnets, and Exfiltration) in real-time when we are completely blind to the payload (due to encryption) and can only passively listen to a unidirectional stream of network metadata?

## 🏗️ Architecture & Tech Stack
This project simulates a real-time, high-speed SOC (Security Operations Center) data pipeline:
1. **Sensor:** Zeek Network Security Monitor logs.
2. **Message Broker:** Redpanda (a high-performance C++ Kafka alternative) buffers the streaming logs.
3. **AI Inference Engine:** A custom Python stream processor evaluates packets in under 1 millisecond.
4. **Triage Dashboard:** An ultra-minimalist Streamlit Web UI for security analysts.

## 🧠 The AI & Detection Engines
To solve the payload-blindness constraint, the system uses a hybrid mix of **Deep Learning, Machine Learning, and Behavioral Statistics** to detect the 6 deadliest threat vectors:

### 1. Dictionary DGA & DNS Tunnelling (Deep Learning)
* **Threat:** Hackers exfiltrate data or find C2 servers using randomized domain names.
* **Solution:** We trained a **PyTorch 1D Convolutional Neural Network (CNN)**. Instead of just looking at entropy, the CNN reads the sequence of characters to catch advanced "Dictionary DGAs" that trick traditional ML algorithms.

### 2. Zero-Day Data Exfiltration (Deep Learning)
* **Threat:** A compromised insider machine starts uploading a database to an unknown IP.
* **Solution:** We trained a **PyTorch Deep Autoencoder**. It was trained purely on benign traffic to learn what "normal" looks like. When exfiltration occurs, the Autoencoder fails to reconstruct the flow, triggering a massive Mean Squared Error (MSE) loss anomaly.

### 3. Botnet C2 Beaconing (Behavioral AI)
* **Threat:** Malware quietly "calls home" to a hacker's command server every few minutes.
* **Solution:** We built a stateful tracker that calculates the **Jitter Coefficient of Variation (CV)**. By tracking the mathematical variance in connection timing, the AI can prove a computer is running an automated script rather than a human clicking links.

### 4. Malware in Encrypted Sessions (Cryptographic Fingerprinting)
* **Threat:** We cannot decrypt the traffic because of the Data Diode.
* **Solution:** We extract **JA3 / JA3S metadata fingerprints** from the initial TLS handshake. The AI instantly cross-references the cryptographic cipher suite against known malware signatures (like Cobalt Strike and Trickbot) without ever needing to decrypt the payload.

### 5. Reconnaissance & Port Scanning (Stateful Tracking)
* **Threat:** An infected IoT device sweeps the internal network for open ports.
* **Solution:** A sliding-window tracking algorithm monitors horizontal and vertical fan-out behavior, flagging attackers who touch too many unique internal assets in a short time frame.

### 6. Volumetric Protocol DDoS (Statistical AI)
* **Threat:** A massive SYN Flood or UDP Reflection attack designed to take down services.
* **Solution:** High-speed velocity calculations track packet-per-second deviations to flag asymmetric traffic spikes.

## 🚀 Key "Wow" Factors for the Demo
* **Lightweight Edge-AI:** Despite using Deep Learning, the compiled `.pt` model binaries weigh less than **1.5 MB** combined. This means it requires ZERO GPUs, runs completely on the CPU, and can be deployed on a cheap Raspberry Pi at the edge of the network.
* **Sub-Millisecond Inference:** By skipping massive LLMs and using targeted neural networks and Scikit-Learn forests, the engine processes and scores threats in microseconds.
* **Enterprise Minimalist UI:** Built for real SOC analysts. No massive JSON dumps or bloated configurations—just ultra-clean critical telemetry and active compromise topology graphs.
* **Live Cloudflare Tunneling:** The dashboard can instantly be routed to the public internet securely using `cloudflared` for remote incident response.
