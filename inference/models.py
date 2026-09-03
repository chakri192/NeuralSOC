import torch
import hashlib
import os
import time
import logging
import unicodedata

logger = logging.getLogger(__name__)

class DeepLearningEngine:
    def __init__(self):
        self.mock_mode = False
        artifact_path = os.getenv("MODEL_PATH", "models/cnn_dga.pt")
        sha_path = artifact_path + ".sha256"
        
        try:
            with open(sha_path, "r") as f:
                expected_sha = f.read().strip()
                
            with open(artifact_path, 'rb') as f:
                file_data = f.read()
                
            computed_sha = hashlib.sha256(file_data).hexdigest()
            
            if computed_sha != expected_sha:
                raise RuntimeError(f"FATAL: Model SHA-256 mismatch! Expected {expected_sha}, got {computed_sha}")
                
            self.model = torch.jit.load(artifact_path, map_location=torch.device('cpu'))
            self.model.eval()
        except Exception as e:
            logger.error(f"[Models] Security/Load Failure: {e}. Falling back to mock.")
            raise RuntimeError(f"Model integrity failure: {e}")

        self.char_map = {chr(i): i - 96 for i in range(97, 123)}
        self.char_map.update({'-': 27, '.': 28})


    def predict(self, features: dict, domain: str = "") -> tuple[bool, float, float]:
        start_time = time.time()
        
            
        if not domain:
            return False, 0.0, time.time() - start_time
            
        # IDNA Defense
        import idna
        normalized = unicodedata.normalize('NFKC', domain)
        try:
                    ascii_domain = idna.encode(normalized, uts46=True).decode('ascii')
        
        # Security Fix: Prevent IDNA drift bypassing padding logic
        if len(ascii_domain) > 35:
            raise RuntimeError("SecurityException: Domain exceeds fixed tensor padding window")
        except Exception:
            raise RuntimeError("SecurityException: Homoglyph / IDNA attack blocked")
            
        domain = ascii_domain.lower()
            
        encoded = [self.char_map.get(c, 0) for c in domain]
        
        if len(encoded) != len(domain) or any(c == 0 for c in encoded):
            raise RuntimeError("SecurityException: Unmapped homoglyph detected")
        
        if len(encoded) > 35:
            raise RuntimeError("SecurityException: Domain exceeds maximum length bound of 35")
        
        encoded = encoded[:35] + [0] * max(0, 35 - len(encoded))
        tensor = torch.tensor([encoded], dtype=torch.float32)

        try:
            with torch.no_grad():
                output = self.model(tensor)
                prob = torch.sigmoid(output).item()
                is_dga = prob > 0.85
                return is_dga, prob, time.time() - start_time
        except Exception as e:
            logger.error(f"[Models] Prediction error: {e}")
            return False, 0.0, time.time() - start_time
