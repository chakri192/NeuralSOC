# 🛡️ AI Cyber Threat Detector - Ultimate Demo Cheat Sheet

Print this out or keep it on a second monitor during your presentation. It covers exactly what to say and how to answer the hardest technical questions.

---

## 1. The Elevator Pitch (30 Seconds)
"We built an Enterprise-Grade, AI-powered Cyber Threat Detection platform designed for highly secure, air-gapped networks. In critical infrastructure (like power plants or financial mainframes), you cannot use inline firewalls because they can be hacked. Instead, networks use **Hardware Data Diodes**—which only allow data to flow *out*. 

Our project solves the ultimate challenge: **How do you detect advanced cyber attacks in real-time when you can only passively listen to encrypted metadata?** We solved this by building a high-speed Kafka streaming pipeline backed by PyTorch Deep Learning models that detect threats in sub-milliseconds without ever decrypting the payload."

---

## 2. The Architecture (How data flows)
1. **The Sensor:** In a real network, an open-source tool like Zeek converts raw packet bytes into JSON metadata. (For this demo, we simulate this feed).
2. **The Shock Absorber:** The JSON logs are streamed into **Redpanda** (a high-performance C++ alternative to Kafka). This prevents the AI from crashing during a massive DDoS attack.
3. **The Engine:** A Python Stream Processor pulls logs from Kafka and runs them through our PyTorch models.
4. **The UI:** The results are pushed to an enterprise-grade Streamlit web dashboard for SOC (Security Operations Center) analysts.

---

## 3. The AI & Threat Models (Crucial Section)

If the judges ask "How does your AI actually work?", use these explanations:

### A. Dictionary DGA (Domain Generation Algorithms)
* **The Threat:** Hackers use randomized domain names (like `xqzjk.com`) to hide command-and-control servers.
* **The AI Model:** **PyTorch 1D-CNN (Convolutional Neural Network)**.
* **How it works:** Instead of just checking if a domain looks "random" (entropy), the CNN reads the sequence of characters like text. It learns spatial patterns (e.g., too many consonants in a row) to catch advanced malware that tricks basic algorithms.

### B. Zero-Day Data Exfiltration
* **The Threat:** An insider or unknown malware uploads a massive database to a random server.
* **The AI Model:** **PyTorch Deep Autoencoder (Unsupervised Learning)**.
* **How it works:** We don't train it on attacks. We only train it on *normal* traffic. The Autoencoder compresses the traffic data and tries to reconstruct it. If it sees a massive data exfiltration, it fails to reconstruct the data, resulting in a huge **Mean Squared Error (MSE) loss**. If MSE spikes, we flag it as an anomaly.

### C. Botnet C2 Beaconing
* **The Threat:** Malware quietly "calls home" every 5 minutes.
* **The AI Model:** **Statistical AI (Jitter Coefficient of Variation)**.
* **How it works:** Humans click links randomly. Scripts operate on math. By calculating the timing variance (Jitter) between connections, we can mathematically prove a connection is automated.

### D. Malware in Encrypted TLS Sessions
* **The Threat:** We can't see the payload because it's encrypted.
* **The Solution:** **Cryptographic Fingerprinting (JA3)**.
* **How it works:** We look at the *metadata* of the initial TLS handshake (how the computer says "hello" to the server). Different malware packages (like Trickbot or Cobalt Strike) use unique ciphers. We fingerprint that "hello" without ever breaking the encryption.

---

## 4. Anticipated Questions & How to Answer Them

**Q: "Can this system actually process raw network traffic (PCAP), or does it only work on your simulated JSON logs?"**
> **A:** "It can absolutely handle raw traffic. We wrote a bridging script in our repository called `pcap_ingester.py` which uses the `scapy` library to read raw bytes off a wire, reassemble the TCP flows, and push them into our Kafka pipeline. We are only using the JSON simulator today to generate enough live volume for the visual demo."

**Q: "If I put this in my company today, will it work out-of-the-box?"**
> **A:** "The architecture will, but the Deep Autoencoder requires a calibration period. This is an Unsupervised Learning model. Just like enterprise tools from Darktrace, our system needs to sit on the client's network for 1-2 weeks in 'Learning Mode'. We provide a `train_dl_models.py` script that the client runs to learn their specific network baseline and compile a custom PyTorch weights file for their company."

**Q: "Why did you use Kafka/Redpanda? Why not just have Python read the logs directly?"**
> **A:** "Because of DDoS attacks. If an attacker floods the network with a million packets a second, a standard Python script will run out of memory and crash, blinding the security team. Kafka acts as a high-speed buffer (a shock absorber) that holds the logs safely until the AI engine can evaluate them."

**Q: "Why did you build this for Apple Silicon / ARM64?"**
> **A:** "We wanted to prove that advanced Deep Learning cybersecurity doesn't require a $10,000 NVIDIA GPU cluster. By compiling targeted, highly-efficient `.pt` models, our entire AI suite weighs less than 2 Megabytes and evaluates threats in sub-milliseconds purely on a standard CPU."
