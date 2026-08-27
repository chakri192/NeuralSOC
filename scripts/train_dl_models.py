#!/usr/bin/env python3
"""
train_dl_models.py
==================
Generates synthetic data and trains PyTorch Deep Learning models
for advanced cyber threat detection.
- Model 1: 1D CNN for Dictionary DGA Detection
- Model 2: Autoencoder for Zero-Day Flow Anomaly Detection
"""

import os
import random
import string
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:
    print("PyTorch is not installed. Please install 'torch' to run this script.")
    exit(1)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# -------------------------------------------------------------------------
# 1. CNN for Dictionary DGA Detection
# -------------------------------------------------------------------------

# Vocabulary: a-z, 0-9, -, . (38 chars max)
CHARS = string.ascii_lowercase + string.digits + "-."
CHAR_TO_IDX = {c: i + 1 for i, c in enumerate(CHARS)}
VOCAB_SIZE = len(CHARS) + 1
MAX_LEN = 64

class DGA_CNN(nn.Module):
    def __init__(self, vocab_size, embed_dim=32, num_filters=64):
        super(DGA_CNN, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(embed_dim, num_filters, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(num_filters, num_filters, kernel_size=5, padding=2)
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.fc1 = nn.Linear(num_filters, 32)
        self.fc2 = nn.Linear(32, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # x: [batch, max_len]
        x = self.embedding(x) # [batch, max_len, embed_dim]
        x = x.transpose(1, 2) # [batch, embed_dim, max_len] (Conv1d expects channels first)
        x = self.relu(self.conv1(x))
        x = self.relu(self.conv2(x))
        x = self.pool(x).squeeze(-1) # [batch, num_filters]
        x = self.relu(self.fc1(x))
        x = self.sigmoid(self.fc2(x))
        return x

def encode_domain(domain):
    encoded = [CHAR_TO_IDX.get(c, 0) for c in domain.lower()[:MAX_LEN]]
    if len(encoded) < MAX_LEN:
        encoded += [0] * (MAX_LEN - len(encoded))
    return encoded

def train_cnn():
    print("[*] Generating Data for DGA CNN...")
    # Synthetic Benign (Normal English-like domains)
    benign_words = ["google", "apple", "microsoft", "amazon", "netflix", "bankofamerica", "github", "linkedin"]
    benign = [f"{random.choice(benign_words)}{random.randint(1,100)}.com" for _ in range(2000)]
    
    # Synthetic Dictionary DGA (E.g. SolarWinds style: valid words strung together)
    dict_words = ["purple", "ocean", "chair", "quantum", "liquid", "shadow", "forest", "crypto"]
    dgas = [f"{random.choice(dict_words)}-{random.choice(dict_words)}-{random.choice(dict_words)}.net" for _ in range(2000)]
    
    # Random DGA (just in case)
    random_dgas = ["".join(random.choices(string.ascii_lowercase, k=random.randint(10,25))) + ".org" for _ in range(1000)]
    
    X_raw = benign + dgas + random_dgas
    y_raw = [0]*len(benign) + [1]*len(dgas) + [1]*len(random_dgas)
    
    X = torch.tensor([encode_domain(d) for d in X_raw], dtype=torch.long)
    y = torch.tensor(y_raw, dtype=torch.float32).unsqueeze(1)
    
    dataset = TensorDataset(X, y)
    loader = DataLoader(dataset, batch_size=64, shuffle=True)
    
    print("[*] Training CNN Model...")
    model = DGA_CNN(VOCAB_SIZE)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005)
    
    model.train()
    for epoch in range(5):
        total_loss = 0
        for batch_x, batch_y in loader:
            optimizer.zero_grad()
            out = model(batch_x)
            loss = criterion(out, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"  Epoch {epoch+1}/5 - Loss: {total_loss/len(loader):.4f}")
        
    save_path = os.path.join(MODEL_DIR, "cnn_dga.pt")
    torch.save(model.state_dict(), save_path)
    print(f"[+] Saved DGA CNN to {save_path}")

# -------------------------------------------------------------------------
# 2. Autoencoder for Zero-Day Flow Anomaly
# -------------------------------------------------------------------------

class FlowAutoencoder(nn.Module):
    def __init__(self, input_dim=5):
        super(FlowAutoencoder, self).__init__()
        # Compression
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 3) # Latent space
        )
        # Reconstruction
        self.decoder = nn.Sequential(
            nn.Linear(3, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim)
        )

    def forward(self, x):
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

def train_autoencoder():
    print("\n[*] Generating Benign Flow Data for Autoencoder...")
    # Features: [log_orig_bytes, log_resp_bytes, log_duration, log_pkts, asymmetry_ratio]
    # We train ONLY on benign data so it learns to reconstruct normal traffic well.
    
    X_train = []
    for _ in range(5000):
        # Web browsing profile
        orig_b = random.uniform(500, 2000)
        resp_b = random.uniform(5000, 500000)
        dur = random.uniform(0.1, 10.0)
        pkts = random.uniform(10, 500)
        ratio = resp_b / max(1.0, orig_b)
        
        vec = [
            np.log1p(orig_b), 
            np.log1p(resp_b), 
            np.log1p(dur), 
            np.log1p(pkts), 
            np.log1p(ratio)
        ]
        X_train.append(vec)
        
    X_tensor = torch.tensor(X_train, dtype=torch.float32)
    # Normalize features roughly to 0-1 range for training stability (using fixed scaling factors for simplicity)
    scaling_factors = torch.tensor([15.0, 15.0, 10.0, 10.0, 10.0], dtype=torch.float32)
    X_tensor = X_tensor / scaling_factors
    
    dataset = TensorDataset(X_tensor, X_tensor) # Autoencoder tries to output its input
    loader = DataLoader(dataset, batch_size=128, shuffle=True)
    
    print("[*] Training Flow Autoencoder...")
    model = FlowAutoencoder(input_dim=5)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    
    model.train()
    for epoch in range(10):
        total_loss = 0
        for batch_x, _ in loader:
            optimizer.zero_grad()
            out = model(batch_x)
            loss = criterion(out, batch_x)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch+1) % 2 == 0:
            print(f"  Epoch {epoch+1}/10 - Reconstruction Loss: {total_loss/len(loader):.6f}")

    save_path = os.path.join(MODEL_DIR, "autoencoder_flow.pt")
    torch.save(model.state_dict(), save_path)
    print(f"[+] Saved Flow Autoencoder to {save_path}")


if __name__ == "__main__":
    train_cnn()
    train_autoencoder()
    print("\n[+] Deep Learning Models successfully generated.")
