import torch
import hashlib
import time
import logging
import unicodedata

logger = logging.getLogger(__name__)

class DeepLearningEngine:
    def __init__(self):
        self.mock_mode = False
        artifact_path = "models/cnn_dga.pt"
        hash_path = artifact_path + ".sha256"
        
        try:
            with open(hash_path, "r") as f:
                self.expected_hash = f.read().strip()
                
            h = hashlib.sha256()
            with open(artifact_path, 'rb') as f:
                while chunk := f.read(65536): 
                    h.update(chunk)
            file_hash = h.hexdigest()
            
            if file_hash != self.expected_hash:
                raise RuntimeError(f"FATAL: Model hash mismatch! Expected {self.expected_hash}, got {file_hash}")
                
            self.model = torch.jit.load(artifact_path, map_location=torch.device('cpu'))
            self.model.eval()
        except Exception as e:
            logger.error(f"[Models] Security/Load Failure: {e}. Falling back to mock.")
            raise RuntimeError(f"Model integrity failure: {e}")

        self.char_map = {chr(i): i - 96 for i in range(97, 123)}
        self.char_map.update({'-': 27, '.': 28})

    def _verify_current_hash(self):
        h = hashlib.sha256()
        with open("models/cnn_dga.pt", 'rb') as f:
            while chunk := f.read(65536): 
                h.update(chunk)
        if h.hexdigest() != self.expected_hash:
            return False
        return True

    def predict(self, features: dict, domain: str = "") -> tuple[bool, float, float]:
        start_time = time.time()
        
        if not self._verify_current_hash():
            raise RuntimeError("SecurityException: Model artifact tampering detected")
            
        if not domain:
            return False, 0.0, time.time() - start_time
            
        # IDNA Defense
        import idna
        normalized = unicodedata.normalize('NFKC', domain)
        try:
            ascii_domain = idna.encode(normalized, uts46=True).decode('ascii')
        except Exception:
            raise RuntimeError("SecurityException: Homoglyph / IDNA attack blocked")
            
        domain = ascii_domain.lower()
            
        encoded = [self.char_map.get(c, 0) for c in domain]
        
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
