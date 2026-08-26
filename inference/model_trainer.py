#!/usr/bin/env python3
"""
model_trainer.py
================
Trains and serializes lightweight Scikit-learn ML models:
1. DGA Detector: Random Forest Classifier for Domain Generation Algorithms.
2. Flow Anomaly Detector: Isolation Forest for data exfiltration and C2 beacon anomalies.

Exports artifacts to the `models/` directory for zero-latency stream scoring.
"""

import os
import random
import string
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score

try:
    from feature_extractor import extract_dns_features, extract_conn_features
except ImportError:
    from inference.feature_extractor import extract_dns_features, extract_conn_features

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# -------------------------------------------------------------
# 1. DGA Dataset Generation & Training
# -------------------------------------------------------------

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "apple.com", "microsoft.com", "amazon.com",
    "facebook.com", "wikipedia.org", "yahoo.com", "reddit.com", "netflix.com",
    "linkedin.com", "twitter.com", "instagram.com", "github.com", "cloudflare.com",
    "office.com", "bing.com", "live.com", "twitch.tv", "adobe.com",
    "spotify.com", "dropbox.com", "slack.com", "zoom.us", "salesforce.com",
    "stackoverflow.com", "medium.com", "nytimes.com", "bbc.co.uk", "cnn.com",
    "ebay.com", "paypal.com", "walmart.com", "target.com", "craigslist.org",
    "imdb.com", "pinterest.com", "tumblr.com", "wordpress.com", "blogger.com",
    "espn.com", "hulu.com", "vimeo.com", "booking.com", "airbnb.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "weather.com", "reuters.com",
    "redhat.com", "ubuntu.com", "debian.org", "nginx.org", "apache.org",
    "python.org", "golang.org", "rust-lang.org", "docker.com", "kubernetes.io",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com", "gitlab.com", "atlassian.com"
]

def generate_synthetic_dga_domains(n: int = 500) -> list:
    """Generates synthetic DGA domains simulating Conficker, Cryptolocker, and Banjori."""
    dga_domains = []
    tlds = ["cc", "xyz", "top", "buzz", "click", "rest", "gq", "info", "ru", "cn"]
    
    # Type 1: High-entropy random alphanumeric string
    for _ in range(n // 2):
        length = random.randint(12, 28)
        body = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        tld = random.choice(tlds)
        dga_domains.append(f"{body}.{tld}")
        
    # Type 2: Consonant-heavy unpronounceable sequence (Conficker style)
    consonants = "bcdfghjklmnpqrstvwxyz"
    for _ in range(n // 4):
        length = random.randint(10, 20)
        body = "".join(random.choices(consonants, k=length))
        tld = random.choice(tlds)
        dga_domains.append(f"{body}.{tld}")
        
    # Type 3: Hex/hash format (Cryptolocker style)
    hex_chars = "0123456789abcdef"
    for _ in range(n // 4):
        length = random.randint(16, 32)
        body = "".join(random.choices(hex_chars, k=length))
        tld = random.choice(tlds)
        dga_domains.append(f"{body}.{tld}")
        
    return dga_domains


def train_dga_detector():
    print("[*] Training DGA Detection Model (Random Forest)...")
    
    benign_samples = BENIGN_DOMAINS * 10  # replicate for balance
    # Add random word-combination benign domains
    words = ["cloud", "secure", "tech", "network", "system", "data", "portal", "stream", "login", "hub", "api"]
    for _ in range(300):
        w1 = random.choice(words)
        w2 = random.choice(words)
        benign_samples.append(f"{w1}-{w2}.com")
        
    dga_samples = generate_synthetic_dga_domains(len(benign_samples))
    
    X = []
    y = []
    
    for domain in benign_samples:
        feats = extract_dns_features(domain)["feature_vector"]
        X.append(feats)
        y.append(0)  # 0 = Benign
        
    for domain in dga_samples:
        feats = extract_dns_features(domain)["feature_vector"]
        X.append(feats)
        y.append(1)  # 1 = DGA
        
    X = np.array(X)
    y = np.array(y)
    
    # Shuffle
    indices = np.arange(len(X))
    np.random.seed(42)
    np.random.shuffle(indices)
    X = X[indices]
    y = y[indices]
    
    # Split
    split = int(0.8 * len(X))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]
    
    clf = RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42, n_jobs=2)
    clf.fit(X_train, y_train)
    
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[+] DGA Detector Test Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, preds, target_names=["Benign", "DGA"]))
    
    model_path = os.path.join(MODEL_DIR, "dga_detector.pkl")
    joblib.dump(clf, model_path)
    print(f"[+] Exported DGA model to: {model_path}\n")
    return clf


# -------------------------------------------------------------
# 2. Flow Anomaly Detection (Isolation Forest)
# -------------------------------------------------------------

def generate_normal_connection_features(n: int = 1500) -> np.ndarray:
    """Generates baseline feature vectors representing typical benign enterprise traffic."""
    vectors = []
    for _ in range(n):
        flow_type = random.choice(["web_browsing", "api_call", "dns_lookup", "small_download"])
        if flow_type == "web_browsing":
            duration = random.uniform(0.1, 15.0)
            orig_bytes = random.randint(500, 5000)
            resp_bytes = random.randint(2000, 150000)
            orig_pkts = random.randint(5, 30)
            resp_pkts = random.randint(10, 120)
        elif flow_type == "api_call":
            duration = random.uniform(0.05, 1.5)
            orig_bytes = random.randint(200, 2000)
            resp_bytes = random.randint(200, 5000)
            orig_pkts = random.randint(3, 10)
            resp_pkts = random.randint(3, 15)
        elif flow_type == "dns_lookup":
            duration = random.uniform(0.01, 0.2)
            orig_bytes = random.randint(40, 120)
            resp_bytes = random.randint(80, 400)
            orig_pkts = 1
            resp_pkts = 1
        else: # small download
            duration = random.uniform(2.0, 30.0)
            orig_bytes = random.randint(1000, 10000)
            resp_bytes = random.randint(50000, 1000000)
            orig_pkts = random.randint(20, 200)
            resp_pkts = random.randint(50, 800)
            
        mock_rec = {
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
        }
        vectors.append(extract_conn_features(mock_rec)["feature_vector"])
        
    return np.array(vectors)


def train_flow_anomaly_detector():
    print("[*] Training Flow Anomaly Detector (Isolation Forest)...")
    X_train = generate_normal_connection_features(2000)
    
    # Contamination set to ~2% expected anomaly rate in production
    iso = IsolationForest(
        n_estimators=60,
        contamination=0.03,
        random_state=42,
        n_jobs=2,
    )
    iso.fit(X_train)
    
    # Test scoring on normal vs anomalous samples
    normal_test = generate_normal_connection_features(5)
    anomalous_exfil = extract_conn_features({
        "duration": 5.2,
        "orig_bytes": 85000000,  # 85 MB outbound!
        "resp_bytes": 200,       # 200 bytes inbound
        "orig_pkts": 58000,
        "resp_pkts": 4,
    })["feature_vector"]
    
    norm_preds = iso.predict(normal_test)
    anom_pred = iso.predict([anomalous_exfil])[0]
    
    print(f"[+] Normal sample predictions (1=Normal): {norm_preds}")
    print(f"[+] Exfiltration sample prediction (-1=Anomaly): {anom_pred}")
    
    model_path = os.path.join(MODEL_DIR, "flow_anomaly.pkl")
    joblib.dump(iso, model_path)
    print(f"[+] Exported Flow Anomaly model to: {model_path}\n")
    return iso


if __name__ == "__main__":
    train_dga_detector()
    train_flow_anomaly_detector()
    print("=" * 60)
    print("ALL MODELS TRAINED AND SERIALIZED SUCCESSFULLY!")
    print("=" * 60)
