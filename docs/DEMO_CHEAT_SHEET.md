#  AI Cyber Threat Detector - Ultimate Demo Cheat Sheet

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
* **The Threat:** Hackers use randomized domain names (like `xqzjk.com`) — or real-word domains built to look legitimate (`whitepepper.su`) — to hide command-and-control servers.
* **The AI Model:** **PyTorch hybrid model** — three parallel 1D-CNN branches (different kernel sizes, so it reads short character n-grams and longer word-fragment-scale patterns at once) plus a small branch of hand-computed lexical stats (entropy, digit/vowel ratio, etc.), combined before the final classifier.
* **How it works:** The CNN branches read the character sequence like text; the lexical branch gives it a second, independent signal that doesn't depend on having seen the exact string before — specifically to catch dictionary-style DGA (real words concatenated together, e.g. `suppobox`/`gozi`), which is deliberately built to defeat pure character-pattern detection.
* **Validated on a real malware capture, not just the benchmark:** run against an actual Lumma Stealer pcap (malware-traffic-analysis.net), it now catches 5 of 7 real suspicious domains in that capture (was 1 of 7 before this rebuild), including the beaconing domain queried 10 times.

### B. Zero-Day Data Exfiltration
* **The Threat:** An insider or unknown malware uploads a massive database to a random server.
* **What's live today, two layers:** A statistical rule flags any single connection sending more than 5MB out while receiving less than 10KB back. Alongside it, a PyTorch Deep Autoencoder (`models/autoencoder_flow.pt`, trained via `inference/train_model.py`'s `train_flow_autoencoder()`) scores the shape of every connection — bytes, duration, packet count — against what it learned as "normal," and flags anything it reconstructs badly (Mean Squared Error above a fixed threshold, computed from held-out validation data at training time). The two are independent and complementary: the rule catches the specific "big upload, tiny response" shape; the autoencoder catches anything that looks behaviorally off, including flows the rule alone would miss.

### C. Botnet C2 Beaconing
* **The Threat:** Malware quietly "calls home" every few minutes.
* **The Detection:** **A statistical rule**, not a neural network — tiny, near-identical payload sizes (50–150 bytes) in both directions, on a port that isn't 80/443/53.
* **How it works:** A heartbeat check-in produces small, repeated, similarly-sized packets on an unusual port — a shape ordinary browsing traffic doesn't have.

### D. Malware in Encrypted TLS Sessions
* **The Threat:** We can't see the payload because it's encrypted.
* **The Solution:** **Cryptographic Fingerprinting — JA4**, not JA3 (JA3 is the older, now-superseded standard; the actual code fingerprints on JA4).
* **How it works:** We look at the *metadata* of the initial TLS handshake (how the computer says "hello" to the server). The full JA4 fingerprint — not just its version prefix, which nearly all modern HTTPS traffic shares — gets matched against a curated list of known-malicious client fingerprints, without ever decrypting the payload. Worth knowing: the shipped default list has one synthetic demo entry, not a real threat-intel feed.

---

## 4. Anticipated Questions & How to Answer Them

**Q: "Can this system actually process raw network traffic (PCAP), or does it only work on your simulated JSON logs?"**
> **A:** "It can absolutely handle raw traffic. We wrote a bridging script in our repository called `pcap_ingester.py` which uses the `scapy` library to read raw bytes off a wire, reassemble the TCP flows, and push them into our Kafka pipeline. We are only using the JSON simulator today to generate enough live volume for the visual demo."

**Q: "If I put this in my company today, will it work out-of-the-box?"**
> **A:** "The rule-based detection, the DGA classifier, and the flow autoencoder all run out of the box today, and both AI models are validated against real-world data now, not just our own simulator. The DGA classifier: a published research dataset of 25 real malware families' actual DGA domains gives us 84.6% precision, 77.2% recall, and a 13.9% false-positive rate. We rebuilt the model specifically to catch dictionary-style DGA it used to miss almost entirely, doubled recall from 38% to 77%, and every one of the 25 families is at or above where it started — we check that automatically on every retrain now, not just the aggregate number. Honest cost: false-positive rate did rise, from 5.9% to 13.9%. The flow autoencoder: we found the same class of problem in it we'd already fixed in the DGA model — synthetic-only training measured a ~98% false-positive rate against a real labeled botnet-traffic dataset — and fixed it the same way: retrained on real data, recalibrated the threshold against the real error distribution, now 100% precision, 99.8% recall, 0.00% false-positive rate on the real held-out set. `inference/train_model.py`'s `train_flow_autoencoder()` still lets a client retrain it further on their own baseline traffic — the same 'Learning Mode' idea enterprise tools like Darktrace use — for their specific network on top of this."

**Q: "Have you actually run this against a real malware sample, not just a labeled dataset?"**
> **A:** "Yes — we downloaded a real, published pcap from malware-traffic-analysis.net (a Lumma Stealer infection capture) and streamed it through the live pipeline end-to-end: real ingester, real Kafka topic, real stream processor, real database. Two real ingester bugs turned up in the process — the connection events weren't tagged with the field every detection rule requires, and DNS queries weren't being extracted from the pcap at all — both fixed, with tests. Once fixed, the DGA classifier caught 5 of the 7 genuinely suspicious domains in that capture, including one queried 10 times in a beaconing pattern. We can walk through the exact domains it caught and missed."

**Q: "Why did you use Kafka/Redpanda? Why not just have Python read the logs directly?"**
> **A:** "Because of DDoS attacks. If an attacker floods the network with a million packets a second, a standard Python script will run out of memory and crash, blinding the security team. Kafka acts as a high-speed buffer (a shock absorber) that holds the logs safely until the AI engine can evaluate them."

**Q: "Why did you build this for Apple Silicon / ARM64?"**
> **A:** "We wanted to prove that advanced Deep Learning cybersecurity doesn't require a $10,000 NVIDIA GPU cluster. By compiling targeted, highly-efficient `.pt` models, our entire AI suite weighs less than 2 Megabytes and evaluates threats in sub-milliseconds purely on a standard CPU."
