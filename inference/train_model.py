import csv
import hashlib
import math
import os
import torch
import torch.nn as nn
import torch.optim as optim
import random
import string
import time
from torch.utils.data import DataLoader, TensorDataset

from inference.models import LEX_DIM, lexical_features


# 1. Hybrid character-CNN + lexical-features architecture.
#
# The original single-branch CNN (kernel size 3 only, twice) measured
# 86.5% precision / 38.1% recall / 5.9% FPR against a real held-out DGA
# benchmark (benchmarks/real_dga_domains.csv), and when run against a real
# Lumma Stealer capture caught only 1 of 7 real dictionary-style malicious
# domains (arch.filemegahab4.sbs) while missing the rest (whitepepper.su,
# megafilehub4.lat, whooptm.cyou, holiday-forever.cc, hiyter.com,
# communicationfirewall-security.cc) -- dictionary-style DGA families are
# deliberately built from real words to defeat exactly this kind of
# character-pattern classifier. Two changes address that directly:
#   1. Multiple parallel conv branches (kernel sizes 3/5/7) instead of one,
#      so the model captures word-fragment-scale patterns as well as
#      short n-grams.
#   2. A parallel lexical-features branch (inference.models.lexical_features:
#      entropy, digit/vowel ratios, unique-char ratio, longest consonant
#      run, hyphen ratio) concatenated in before the final classifier --
#      an independent signal that doesn't depend on having seen the exact
#      character sequence before, unlike the embedding+conv path alone.
class DGA_HybridModel(nn.Module):
    def __init__(self, vocab_size=39, embed_dim=32, lex_dim=LEX_DIM, num_classes=1):
        super(DGA_HybridModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv3 = nn.Conv1d(embed_dim, 96, kernel_size=3, padding=1)
        self.conv5 = nn.Conv1d(embed_dim, 96, kernel_size=5, padding=2)
        self.conv7 = nn.Conv1d(embed_dim, 96, kernel_size=7, padding=3)
        self.relu = nn.ReLU()
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.lex_fc = nn.Linear(lex_dim, 16)
        self.fc1 = nn.Linear(96 * 3 + 16, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x, lex):
        emb = self.embedding(x)
        emb = emb.permute(0, 2, 1)
        b3 = self.pool(self.relu(self.conv3(emb))).squeeze(2)
        b5 = self.pool(self.relu(self.conv5(emb))).squeeze(2)
        b7 = self.pool(self.relu(self.conv7(emb))).squeeze(2)
        conv_out = torch.cat([b3, b5, b7], dim=1)
        lex_out = self.relu(self.lex_fc(lex))
        combined = torch.cat([conv_out, lex_out], dim=1)
        h = self.relu(self.fc1(combined))
        return self.sigmoid(self.fc2(h))

_BENIGN_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_benign_domains_train.csv")
_FALLBACK_BENIGN_DOMAINS = ["google.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com", "github.com", "ubuntu.com", "wikipedia.org", "yahoo.com", "linkedin.com"]

_REAL_DGA_AUGMENT_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "real_dga_domains_train_augment.csv")
_DICTIONARY_SEED_WORD_PATHS = [
    os.path.join(os.path.dirname(__file__), "..", "benchmarks", f"dictionary_dga_seed_words_{i}.txt")
    for i in (1, 2, 3)
]
_MALICIOUS_TLDS = [".com", ".net", ".org", ".biz", ".info", ".sbs", ".cc", ".cyou", ".lat", ".su", ".top", ".xyz", ".ru", ".tk"]

# Structurally similar to (never copied from) real service-discovery/
# telemetry domains observed as CNN false positives when this pipeline
# was run against a real Lumma Stealer pcap: legitimate compound Windows
# AD/mDNS service records and Microsoft telemetry endpoints, whose long,
# multi-label, subdomain-heavy shape superficially resembles a DGA/DNS-
# tunnelling domain to a purely character-sequence classifier.
_SERVICE_DISCOVERY_LABELS = [
    "_ldap._tcp.Default-First-Site-Name._sites",
    "_ldap._tcp.dc._msdcs",
    "_kerberos._tcp.dc._msdcs",
    "wpad",
    "isatap",
]
_TELEMETRY_HOSTS = [
    "watson.events.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com",
]


def _load_real_dga_augment_domains():
    """Real dictionary/hyphenated-style DGA domains (suppobox, gozi,
    nymaim, nymaim2, proslikefan, symmi, charbot, corebot, necurs),
    sourced from github.com/baderj/domain_generation_algorithms -- a
    different source than benchmarks/real_dga_domains.csv (the held-out
    real-world test set, from chrmor/DGA_domains_dataset), with a
    verified zero-overlap check against that test set at build time.
    Directly targets the dictionary-DGA recall gap: the CNN previously
    caught only 1 of 7 real dictionary-style malicious domains from a
    live Lumma Stealer pcap test.
    """
    if not os.path.exists(_REAL_DGA_AUGMENT_PATH):
        return []
    domains = []
    with open(_REAL_DGA_AUGMENT_PATH, encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) >= 3:
                domains.append(row[2].strip().lower())
    return domains


def _load_dictionary_seed_words():
    """The suppobox family's own real seed word corpora (three versions of
    its word lists) -- generating fresh word1+word2 combinations from
    these goes beyond the ~250 static example domains above for this
    specific family, without inventing an unrelated word list."""
    word_lists = []
    for path in _DICTIONARY_SEED_WORD_PATHS:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                words = [w.strip().lower() for w in f if w.strip()]
            if words:
                word_lists.append(words)
    return word_lists


def _generate_dictionary_dga(word_lists):
    if not word_lists:
        fallback = ["login", "admin", "secure", "update", "verify", "account", "portal", "support", "billing", "auth"]
        word_lists = [fallback, fallback]
    list_a = random.choice(word_lists)  # nosec B311
    list_b = random.choice(word_lists)  # nosec B311
    w1 = random.choice(list_a)  # nosec B311
    w2 = random.choice(list_b)  # nosec B311
    # nymaim2-style hyphenated concatenation ~40% of the time, suppobox-
    # style bare concatenation otherwise -- both are real, observed
    # patterns among the family examples above.
    sep = "-" if random.random() < 0.4 else ""  # nosec B311
    return f"{w1}{sep}{w2}{random.choice(_MALICIOUS_TLDS)}"  # nosec B311


def _extract_check_worthy_label(domain: str):
    """Mirrors inference/models.py's own multi-segment defense: for a
    domain with dots, DeepLearningEngine._predict_impl independently
    re-scores every subdomain label >= 4 chars on its own, dot-free, to
    catch DNS-tunnelling hidden in a single label. Without matching bare-
    label examples in training, that check is scoring wildly
    out-of-distribution inputs -- confirmed empirically: the model scored
    every bare label tested ("google", "mail", "www", "cdn", ...) near
    1.0 regardless of legitimacy, which single-handedly explained a 93%
    false-positive rate on the real benchmark (every multi-label domain
    has an apex label >= 4 chars). Feeding the model labeled bare-label
    examples of both classes during training closes that gap directly.
    """
    parts = [p for p in domain.split('.') if len(p) >= 4]
    return random.choice(parts) if parts else None  # nosec B311


def _generate_service_discovery_benign(benign_domains):
    base = random.choice(benign_domains)  # nosec B311
    choice = random.random()  # nosec B311
    if choice < 0.3:
        return f"{random.choice(_SERVICE_DISCOVERY_LABELS)}.{base}"  # nosec B311
    elif choice < 0.55:
        return random.choice(_TELEMETRY_HOSTS)  # nosec B311
    elif choice < 0.7:
        return "_googlecast._tcp.local"
    else:
        sub = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))  # nosec B311
        return f"{sub}.{base}"


def _load_benign_domains():
    """40,000 real domains sampled across Tranco's full popularity range
    (benchmarks/real_benign_domains_train.csv), not just a handful of
    world-famous brand names.

    The model used to train on exactly 10 hardcoded benign domains
    (google.com, apple.com, ...) -- confirmed, empirically, to be the
    root cause of a 98% false-positive rate when the resulting CNN was
    actually run against benchmarks/real_dga_domains.csv's real Alexa
    domains (scripts/evaluate_against_real_dga_dataset.py): the model
    had learned "matches one of these 10 exact strings" rather than any
    general notion of what a legitimate domain looks like, so anything
    outside that tiny set -- i.e. nearly every real domain that exists --
    read as anomalous. Deliberately excludes every domain already used
    in that held-out real test set, so training and evaluation never
    see the same benign domains.
    """
    if os.path.exists(_BENIGN_DOMAINS_PATH):
        with open(_BENIGN_DOMAINS_PATH, encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]
        if domains:
            return domains
    return _FALLBACK_BENIGN_DOMAINS


# 2. Hardened Threat Generator (real + synthetic dataset creation for ML training)
def generate_hard_dataset(num_samples=100000):
    char_map = {c: i+1 for i, c in enumerate(string.ascii_lowercase + string.digits + "-.")}
    benign_domains = _load_benign_domains()
    real_dga_domains = _load_real_dga_augment_domains()
    dictionary_word_lists = _load_dictionary_seed_words()

    data, labels = [], []
    for _ in range(num_samples // 2):
        # Generate Difficult Malicious Threats
        threat_type = random.random()  # nosec B311
        if real_dga_domains and threat_type < 0.30:
            # 1. Real dictionary/hyphenated-style DGA domains (suppobox,
            # gozi, nymaim, nymaim2, proslikefan, symmi, charbot, corebot,
            # necurs) -- see _load_real_dga_augment_domains().
            dga = random.choice(real_dga_domains)  # nosec B311
        elif threat_type < 0.55:
            # 2. Synthetic dictionary DGA generated from the same real
            # word corpora, for volume/diversity beyond the ~4,340 static
            # real examples above.
            dga = _generate_dictionary_dga(dictionary_word_lists)
        elif threat_type < 0.80:
            # 3. Homoglyph Attack (Typosquatting)
            base = random.choice(benign_domains)  # nosec B311
            dga = base.replace('o', '0').replace('l', '1').replace('i', '1').replace('e', '3')
            if dga == base:
                dga = "g00gle.com"
        else:
            # 4. Standard Corebot/Cryptolocker
            length = random.randint(15, 25)  # nosec B311
            dga = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".com"  # nosec B311

        data.append(dga)
        labels.append(1.0)

        # Bare-label training examples -- see _extract_check_worthy_label()'s
        # docstring. ~35% of the time, also teach the model this exact
        # malicious label in isolation (no TLD, no dots).
        if random.random() < 0.35:  # nosec B311
            bare = _extract_check_worthy_label(dga)
            if bare:
                data.append(bare)
                labels.append(1.0)

        # Generate Benign
        benign_type = random.random()  # nosec B311
        base = random.choice(benign_domains)  # nosec B311
        if benign_type < 0.3:
            # Hard negatives: compound service-discovery/telemetry-shaped
            # domains -- see _generate_service_discovery_benign()'s
            # docstring for why these matter.
            benign_domain = _generate_service_discovery_benign(benign_domains)
        elif benign_type < 0.65:
            prefix = random.choice(["www", "api", "mail", "dev", "staging"])  # nosec B311
            benign_domain = f"{prefix}.{base}"
        else:
            benign_domain = base
        data.append(benign_domain)
        labels.append(0.0)

        # Same bare-label augmentation for the benign side -- an ordinary
        # apex/subdomain label (e.g. "google" from "google.com") on its
        # own is exactly what the multi-segment defense evaluates and
        # must NOT be treated as inherently suspicious just for lacking a
        # dot.
        if random.random() < 0.35:  # nosec B311
            bare = _extract_check_worthy_label(benign_domain)
            if bare:
                data.append(bare)
                labels.append(0.0)

    dataset = list(zip(data, labels))
    random.shuffle(dataset)  # nosec B311
    data, labels = zip(*dataset)

    max_len = 35
    encoded_data = []
    lex_data = []
    for d in data:
        d_lower = d.lower()[:max_len]
        encoded = [char_map.get(c, 0) for c in d_lower]
        if len(encoded) < max_len:
            encoded += [0] * (max_len - len(encoded))
        encoded_data.append(encoded[:max_len])
        lex_data.append(lexical_features(d_lower))

    return (
        torch.tensor(encoded_data, dtype=torch.long),
        torch.tensor(lex_data, dtype=torch.float32),
        torch.tensor(labels, dtype=torch.float32).unsqueeze(1),
    )


def save_traced_model(traced_model, save_path):
    """Persist a traced model and its sidecar .sha256 together.

    Without the sidecar, the next DeepLearningEngine startup's (correctly
    fail-safe) integrity check finds a stale/missing .sha256, fails closed,
    and crash-loops the fleet. scripts/train_dl_models.py already does this
    correctly -- pulled out as its own function here so it's testable
    without running a full training loop.
    """
    traced_model.save(save_path)
    with open(save_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    with open(save_path + ".sha256", "w") as f:
        f.write(file_hash + "\n")
    return file_hash

def train_to_max():
    print("[*] Generating Hardened Training Dataset (100,000 domains)...")
    print("[*] Incorporating real DGA families, dictionary DGAs, homoglyphs, and hard-negative benign patterns...")
    X_char, X_lex, y = generate_hard_dataset(100000)

    split_idx = int(len(X_char) * 0.8)
    X_char_train, X_lex_train, y_train = X_char[:split_idx], X_lex[:split_idx], y[:split_idx]
    X_char_val, X_lex_val, y_val = X_char[split_idx:], X_lex[split_idx:], y[split_idx:]

    # Mini-batched, not one full-batch gradient step per "epoch" -- the
    # latter was confirmed to matter, not just theoretically: with 50
    # *total* optimizer steps for the whole run, it trained fine against
    # the old benign set (10 hardcoded famous domains, a trivially
    # separable task) but collapsed to predicting "not DGA" for
    # everything the moment the benign set became 40,000 genuinely
    # diverse real domains (scripts/evaluate_against_real_dga_dataset.py
    # went from a 98% false-positive rate straight to 0% recall) -- a
    # harder, more realistic decision boundary needs real gradient signal
    # accumulated over many steps, not one giant averaged-out step.
    train_loader = DataLoader(TensorDataset(X_char_train, X_lex_train, y_train), batch_size=256, shuffle=True)

    model = DGA_HybridModel()
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    print("\n[*] Commencing Maximum Precision Training Loop...")

    best_acc = 0.0
    target_acc = 99.95
    patience = 8
    epochs_no_improve = 0
    epoch = 0

    os.makedirs("models", exist_ok=True)

    while best_acc < target_acc and epochs_no_improve < patience and epoch < 50:
        epoch += 1
        model.train()
        for batch_x, batch_lex, batch_y in train_loader:
            optimizer.zero_grad()
            loss = criterion(model(batch_x, batch_lex), batch_y)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_preds = model(X_char_val, X_lex_val)
            val_loss = criterion(val_preds, y_val)
            predictions = (val_preds > 0.5).float()
            accuracy = (predictions == y_val).float().mean() * 100

        acc_val = accuracy.item()

        if acc_val > best_acc:
            print(f"    Epoch {epoch:02d} | Val Accuracy: {acc_val:.3f}% (NEW BEST) | Saved Weights")
            best_acc = acc_val
            epochs_no_improve = 0

            traced_model = torch.jit.trace(
                model,
                (torch.zeros((1, 35), dtype=torch.long), torch.zeros((1, LEX_DIM), dtype=torch.float32)),
            )
            save_path = "models/cnn_dga.pt"
            save_traced_model(traced_model, save_path)
        else:
            print(f"    Epoch {epoch:02d} | Val Accuracy: {acc_val:.3f}% (No improvement)")
            epochs_no_improve += 1

    print(f"\n[*] Training halted. Maximum achievable accuracy on Hard Dataset: {best_acc:.3f}%")
    print("[*] Best model weights locked into production.")


# 3. Flow Autoencoder (behavioral anomaly detection on connection shape,
# not domain names -- see inference/models.py's FlowAnomalyEngine for how
# this gets used at inference time).
class FlowAutoencoder(nn.Module):
    def __init__(self, input_dim=5):
        super(FlowAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 3),
        )
        self.decoder = nn.Sequential(
            nn.Linear(3, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# Must exactly match inference/models.py's FLOW_FEATURE_SCALE and
# flow_feature_vector() -- this is what the model is trained to expect,
# and a mismatch between training and inference scaling would silently
# make every real flow look anomalous (or none look anomalous) without
# either side raising an error.
FLOW_FEATURE_SCALE = [15.0, 15.0, 10.0, 10.0, 10.0]


def generate_benign_flow_dataset(num_samples=20000):
    """Synthetic "normal" connection flows only -- an autoencoder is
    trained to reconstruct what it's shown, so training it on anything
    but benign traffic would teach it to faithfully reconstruct attack
    traffic too, defeating the entire approach. Ranges chosen to look
    like ordinary client/server request-response traffic: a modest
    request, a larger response, sub-10-second duration, tens to hundreds
    of packets -- deliberately not calibrated against any real network's
    actual baseline, which is exactly why FlowAnomalyEngine's own
    docstring is upfront that this hasn't been validated against real
    traffic.
    """
    rows = []
    for _ in range(num_samples):
        orig_bytes = random.uniform(500, 2000)
        resp_bytes = random.uniform(5000, 500000)
        duration = random.uniform(0.1, 10.0)
        orig_pkts = random.uniform(10, 500)
        ratio = resp_bytes / max(1.0, orig_bytes)
        raw = [
            math.log1p(orig_bytes),
            math.log1p(resp_bytes),
            math.log1p(duration),
            math.log1p(orig_pkts),
            math.log1p(ratio),
        ]
        rows.append([v / s for v, s in zip(raw, FLOW_FEATURE_SCALE)])
    return torch.tensor(rows, dtype=torch.float32)


def train_flow_autoencoder():
    print("\n[*] Generating Benign Flow Dataset for Autoencoder (20,000 samples)...")
    X = generate_benign_flow_dataset(20000)
    split_idx = int(len(X) * 0.8)
    X_train, X_val = X[:split_idx], X[split_idx:]

    model = FlowAutoencoder()
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    print("[*] Training Flow Autoencoder...")
    best_val_loss = float("inf")
    patience = 5
    epochs_no_improve = 0
    epoch = 0
    while epochs_no_improve < patience and epoch < 100:
        epoch += 1
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), X_train)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_loss = criterion(model(X_val), X_val).item()

        if val_loss < best_val_loss - 1e-6:
            best_val_loss = val_loss
            epochs_no_improve = 0
            if epoch % 10 == 0 or epoch == 1:
                print(f"    Epoch {epoch:03d} | Val Reconstruction Loss: {val_loss:.6f} (NEW BEST)")
        else:
            epochs_no_improve += 1

    # Anomaly threshold: mean + 4 standard deviations of *per-sample*
    # validation reconstruction error -- not the batch-mean loss above,
    # which would treat one wildly anomalous sample identically to a
    # thousand slightly-off ones. Computed on held-out validation data
    # (never trained on) so this reflects genuine generalization error,
    # not the model's ability to memorize its own training set.
    model.eval()
    with torch.no_grad():
        recon = model(X_val)
        per_sample_error = torch.mean((recon - X_val) ** 2, dim=1)
    threshold = float(per_sample_error.mean().item() + 4 * per_sample_error.std().item())
    print(f"[*] Training halted after {epoch} epochs. Anomaly threshold (mean + 4sd): {threshold:.6f}")

    os.makedirs("models", exist_ok=True)
    traced_model = torch.jit.trace(model, torch.zeros((1, 5), dtype=torch.float32))
    save_path = "models/autoencoder_flow.pt"
    save_traced_model(traced_model, save_path)
    with open(save_path + ".threshold", "w") as f:
        f.write(f"{threshold:.8f}\n")
    print(f"[+] Saved Flow Autoencoder to {save_path} (+ .sha256, + .threshold)")


if __name__ == "__main__":
    train_to_max()
    train_flow_autoencoder()
