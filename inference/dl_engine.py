import os
import string
import numpy as np

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

# Reproduce CNN Architecture
CHARS = string.ascii_lowercase + string.digits + "-."
CHAR_TO_IDX = {c: i + 1 for i, c in enumerate(CHARS)}
VOCAB_SIZE = len(CHARS) + 1
MAX_LEN = 64

if TORCH_AVAILABLE:
    class DGA_CNN(nn.Module):
        def __init__(self, vocab_size=VOCAB_SIZE, embed_dim=32, num_filters=64):
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
            x = self.embedding(x)
            x = x.transpose(1, 2)
            x = self.relu(self.conv1(x))
            x = self.relu(self.conv2(x))
            x = self.pool(x).squeeze(-1)
            x = self.relu(self.fc1(x))
            x = self.sigmoid(self.fc2(x))
            return x

    class FlowAutoencoder(nn.Module):
        def __init__(self, input_dim=5):
            super(FlowAutoencoder, self).__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 16), nn.ReLU(),
                nn.Linear(16, 8), nn.ReLU(),
                nn.Linear(8, 3)
            )
            self.decoder = nn.Sequential(
                nn.Linear(3, 8), nn.ReLU(),
                nn.Linear(8, 16), nn.ReLU(),
                nn.Linear(16, input_dim)
            )

        def forward(self, x):
            latent = self.encoder(x)
            return self.decoder(latent)

class DeepLearningEngine:
    def __init__(self):
        self.cnn_model = None
        self.ae_model = None
        if TORCH_AVAILABLE:
            self._load_models()

    def _load_models(self):
        cnn_path = os.path.join(MODEL_DIR, "cnn_dga.pt")
        ae_path = os.path.join(MODEL_DIR, "autoencoder_flow.pt")

        if os.path.exists(cnn_path):
            self.cnn_model = DGA_CNN()
            self.cnn_model.load_state_dict(torch.load(cnn_path, map_location=torch.device('cpu')))
            self.cnn_model.eval()

        if os.path.exists(ae_path):
            self.ae_model = FlowAutoencoder()
            self.ae_model.load_state_dict(torch.load(ae_path, map_location=torch.device('cpu')))
            self.ae_model.eval()

    def _encode_domain(self, domain: str):
        encoded = [CHAR_TO_IDX.get(c, 0) for c in domain.lower()[:MAX_LEN]]
        if len(encoded) < MAX_LEN:
            encoded += [0] * (MAX_LEN - len(encoded))
        return torch.tensor([encoded], dtype=torch.long)

    def evaluate_dns(self, query: str) -> float:
        """Returns CNN probability (0.0 to 1.0) of being a dictionary DGA."""
        if not self.cnn_model or not query:
            return 0.0
        with torch.no_grad():
            tensor = self._encode_domain(query)
            prob = self.cnn_model(tensor).item()
        return prob

    def evaluate_flow(self, orig_b: float, resp_b: float, dur: float, pkts: float) -> float:
        """Returns Autoencoder reconstruction error (higher = more anomalous)."""
        if not self.ae_model:
            return 0.0
        
        ratio = resp_b / max(1.0, orig_b)
        vec = [np.log1p(orig_b), np.log1p(resp_b), np.log1p(dur), np.log1p(pkts), np.log1p(ratio)]
        
        with torch.no_grad():
            x = torch.tensor([vec], dtype=torch.float32)
            scaling = torch.tensor([15.0, 15.0, 10.0, 10.0, 10.0], dtype=torch.float32)
            x_scaled = x / scaling
            
            reconstructed = self.ae_model(x_scaled)
            mse_loss = nn.MSELoss()(reconstructed, x_scaled).item()
            
        return mse_loss
