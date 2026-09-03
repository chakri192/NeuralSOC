import torch
import os
import io
import hashlib
import unicodedata
import idna
import logging
import time

logger = logging.getLogger(__name__)

# F20: Cap PyTorch threads
torch.set_num_threads(1)
torch.set_num_interop_threads(1)

class DeepLearningEngine:
    def __init__(self):
        self.model = None
        artifact_path = os.getenv("MODEL_PATH", "models/cnn_dga.pt")
        sha_path = artifact_path + ".sha256"
        try:
            fd_bin = os.open(artifact_path, os.O_RDONLY)
            fd_sha = os.open(sha_path, os.O_RDONLY)
            with os.fdopen(fd_bin, 'rb') as f_bin, os.fdopen(fd_sha, 'r') as f_sha:
                model_bytes = f_bin.read()
                expected_sha = f_sha.read().strip()
            
            if hashlib.sha256(model_bytes).hexdigest() != expected_sha:
                raise RuntimeError("Integrity Error: SHA-256 mismatch")
                
            self.model = torch.jit.load(io.BytesIO(model_bytes), map_location=torch.device('cpu'))
            self.model.eval()
        except Exception as e:
            logger.error(f"Model initialization failure: {e}")
            raise
            
        self.char_map = {chr(i): i for i in range(32, 127)}

    def predict(self, features: dict, domain: str = ""):
        if not domain or not self.model:
            return False, 0.0, 0.0
            
        try:
            normalized = unicodedata.normalize('NFKC', domain)
            ascii_domain = idna.encode(normalized, uts46=True).decode('ascii').lower()
            encoded = [self.char_map.get(c, 0) for c in ascii_domain]
            if len(encoded) == 0 or len(encoded) != len(ascii_domain) or any(c == 0 for c in encoded):
                return False, 0.0, 0.0
            
            encoded = encoded[:35] + [0] * max(0, 35 - len(encoded))
            tensor = torch.tensor([encoded], dtype=torch.long)
            
            with torch.no_grad():
                prob = self.model(tensor).item()
                return prob > 0.85, prob, 0.1
        except idna.core.IDNAError:
            return False, 0.0, 0.0
        except Exception as e:
            logger.error(f"Prediction Error: {e}")
            raise RuntimeError("Prediction Error")
