import os
import sys
import time
import random
import string
import hashlib
import traceback

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from inference.train_model import DGA_CNN
except Exception as e:
    print(f"Failed to import ML libraries: {e}")
    sys.exit(1)

def generate_procedural_word(min_len=4, max_len=10):
    """Generates mathematically vast combinations of English-sounding syllables."""
    vowels = "aeiou"
    consonants = "bcdfghjklmnpqrstvwxyz"
    word = ""
    for i in range(random.randint(min_len, max_len)):
        if i % 2 == 0:
            word += random.choice(consonants)
        else:
            word += random.choice(vowels)
    return word

def generate_dynamic_dataset(num_samples, difficulty="medium"):
    char_map = {c: i+1 for i, c in enumerate(string.ascii_lowercase + string.digits + "-.")}
    
    # Base TLDs and common tech terms to mix in
    tlds = [".com", ".net", ".org", ".io", ".co", ".biz", ".info"]
    tech_prefixes = ["api", "cdn", "auth", "mail", "dev", "app", "cloud", "sys", "web"]
    
    data, labels = [], []
    for _ in range(num_samples // 2):
        
        # ==========================================
        # 1. INFINITE MALICIOUS GENERATOR (Label 1)
        # ==========================================
        threat_type = random.random()
        
        if threat_type < 0.25:
            real_words = ['apple', 'ocean', 'chair', 'quantum', 'liquid', 'shadow', 'forest', 'crypto', 'solar', 'winds', 'purple', 'mountain', 'river', 'stone', 'eagle', 'login', 'admin', 'secure', 'update', 'verify', 'account', 'portal', 'support', 'billing', 'auth']
            # Type A: True Dictionary DGA
            if random.random() > 0.5:
                parts = [random.choice(real_words) for _ in range(random.randint(2, 4))]
            else:
                parts = [generate_procedural_word(4, 7) for _ in range(random.randint(2, 4))]
            dga = "-".join(parts) + random.choice(tlds)
            
        elif threat_type < 0.50:
            # Type B: Infinite Hex/Alphanumeric (Cryptolocker style)
            # Example: "a8f93bc812de.net"
            charset = string.ascii_lowercase + string.digits if difficulty == "extreme" else string.ascii_lowercase
            dga = ''.join(random.choices(charset, k=random.randint(12, 30))) + random.choice(tlds)
            
        elif threat_type < 0.75:
            # Type C: Infinite Subdomain Tunneling (DNS Exfiltration)
            # Example: "12398412893712984.data.bikor.com"
            payload = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(20, 30)))
            base = generate_procedural_word(5, 8)
            dga = f"{payload}.{random.choice(tech_prefixes)}.{base}{random.choice(tlds)}"
            
        else:
            # Type D: Advanced Homoglyphs and Typosquatting
            # Procedurally mutates benign-looking words
            base = generate_procedural_word(6, 12)
            mutations = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5'}
            for char, mut in mutations.items():
                if random.random() > (0.2 if difficulty == "extreme" else 0.5):
                    base = base.replace(char, mut)
            dga = f"{random.choice(tech_prefixes)}-{base}{random.choice(tlds)}"
            
        data.append(dga)
        labels.append(1.0)
        
        # ==========================================
        # 2. INFINITE BENIGN GENERATOR (Label 0)
        # ==========================================
        # We must generate procedurally infinite benign traffic to prevent 
        # the model from just memorizing our exact DGA functions.
        
        benign_base = generate_procedural_word(5, 12)
        
        # Sometimes add numbers to benign to confuse the AI
        if random.random() > 0.7:
            benign_base += str(random.randint(1, 999))
            
        # Add realistic subdomain structures
        if random.random() > 0.4:
            sub = random.choice(tech_prefixes)
            if random.random() > 0.5:
                # e.g., api-v3
                sub += f"-v{random.randint(1,5)}"
            benign = f"{sub}.{benign_base}{random.choice(tlds)}"
        else:
            benign = f"{benign_base}{random.choice(tlds)}"
            
        data.append(benign)
        labels.append(0.0)
        
    dataset = list(zip(data, labels))
    random.shuffle(dataset)
    data, labels = zip(*dataset)
    
    max_len = 35
    encoded_data = []
    for d in data:
        encoded = [char_map.get(c, 0) for c in d.lower()]
        if len(encoded) < max_len: encoded += [0] * (max_len - len(encoded))
        encoded_data.append(encoded[:max_len])
        
    return torch.tensor(encoded_data, dtype=torch.long), torch.tensor(labels, dtype=torch.float32).unsqueeze(1)


def continuous_train_loop():
    print("[*] Starting INFINITE Procedural Auto-Trainer (DevSecOps Agent)...")
    os.makedirs("models", exist_ok=True)
    
    cycle = 1
    while True:
        try:
            difficulty = random.choice(["medium", "hard", "extreme"])
            samples = random.choice([50000, 100000, 200000])
            lr = random.choice([0.001, 0.0005, 0.002])
            
            print(f"\n=======================================================")
            print(f"[*] Cycle {cycle} | Difficulty: {difficulty.upper()} | Samples: {samples:,} | LR: {lr}")
            print(f"=======================================================")
            
            X, y = generate_dynamic_dataset(samples, difficulty=difficulty)
            
            split_idx = int(len(X) * 0.8)
            X_train, y_train = X[:split_idx], y[:split_idx]
            X_val, y_val = X[split_idx:], y[split_idx:]
            
            model = DGA_CNN()
            criterion = nn.BCELoss()
            optimizer = optim.Adam(model.parameters(), lr=lr)
            
            best_acc = 0.0
            patience = 5
            epochs_no_improve = 0
            epoch = 0
            
            from torch.utils.data import TensorDataset, DataLoader
            train_dataset = TensorDataset(X_train, y_train)
            train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True)
            
            while epochs_no_improve < patience and epoch < 30:
                epoch += 1
                model.train()
                for batch_x, batch_y in train_loader:
                    optimizer.zero_grad()
                    loss = criterion(model(batch_x), batch_y)
                    loss.backward()
                    optimizer.step()
                
                model.eval()
                with torch.no_grad():
                    val_preds = model(X_val) # X_val is small enough (20%) or should be batched. Let's batch val too to be safe.
                
                val_dataset = TensorDataset(X_val, y_val)
                val_loader = DataLoader(val_dataset, batch_size=512)
                correct = 0
                total = 0
                with torch.no_grad():
                    for batch_x, batch_y in val_loader:
                        preds = model(batch_x)
                        predictions = (preds > 0.5).float()
                        correct += (predictions == batch_y).float().sum().item()
                        total += len(batch_y)
                accuracy = (correct / total) * 100
                    
                acc_val = float(accuracy)
                
                if acc_val > best_acc:
                    print(f"    Epoch {epoch:02d} | Val Accuracy: {acc_val:.3f}% (NEW BEST)")
                    best_acc = acc_val
                    epochs_no_improve = 0
                    
                    traced_model = torch.jit.trace(model, torch.zeros((1, 35), dtype=torch.long))
                    traced_model.save("models/cnn_dga_temp.pt")
                else:
                    print(f"    Epoch {epoch:02d} | Val Accuracy: {acc_val:.3f}%")
                    epochs_no_improve += 1
                    
            print(f"[*] Cycle {cycle} Complete. Max Accuracy: {best_acc:.3f}%. Deploying to production...")
            
            os.replace("models/cnn_dga_temp.pt", "models/cnn_dga.pt")
            
            with open("models/cnn_dga.pt", 'rb') as f:
                new_hash = hashlib.sha256(f.read()).hexdigest()
            with open("models/cnn_dga.pt.sha256", 'w') as f:
                f.write(new_hash)
                
            print(f"[+] Deployed New Secure Model Hash: {new_hash}")
            cycle += 1
            
            print("[*] Cooling down for 30 seconds...")
            time.sleep(30)
            
        except Exception as e:
            print(f"[!] Auto-Trainer Encountered Fatal Error: {e}")
            traceback.print_exc()
            print("[!] Restarting cycle in 10 seconds to ensure continuous execution...")
            time.sleep(10)

if __name__ == "__main__":
    continuous_train_loop()
