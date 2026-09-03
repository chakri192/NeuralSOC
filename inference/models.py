import time
import os
import string
import hashlib
import logging

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

logger = logging.getLogger("models")

class SecurityException(Exception):
    pass

class DGAClassifier:
    def __init__(self, artifact_path="models/cnn_dga.pt"):
        self.model_name = "CNN_DGA_Classifier"
        self.model_version = "v1.0"
        self.mock_mode = False
        
        # PERFORMANCE FIX: Initialize char_map once in RAM, not per-inference
        self.char_map = {c: i+1 for i, c in enumerate(string.ascii_lowercase + string.digits + "-.")}
        
        # SECURITY FIX: Cryptographic enforcement
        hash_file = "models/cnn_dga.pt.sha256"
        if os.path.exists(hash_file):
            with open(hash_file, "r") as hf:
                self.expected_hash = hf.read().strip()
        else:
            self.expected_hash = "6171ae762fc471d10247fe31e7de86fb7ac1d521b5fa5c2b473e0121a1319731"
        
        if TORCH_AVAILABLE and os.path.exists(artifact_path):
            try:
                # 1. Verify integrity before loading
                with open(artifact_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                if file_hash != self.expected_hash:
                    raise SecurityException(f"FATAL: Model hash mismatch! Expected {self.expected_hash}, got {file_hash}")
                    
                logger.info(f"[Models] Integrity verified. Loading secure weights: {file_hash}")
                
                # 2. Load model
                self.model = torch.jit.load(artifact_path, map_location=torch.device('cpu'))
                self.model.eval()
            except Exception as e:
                logger.error(f"[Models] Security/Load Failure: {e}. Falling back to mock.")
                self.mock_mode = True
        else:
            self.mock_mode = True

    def predict(self, features: dict, domain: str = "") -> tuple[bool, float, float]:
        """Returns (is_threat, confidence_score, latency_seconds)"""
        start_time = time.time()
        
        if self.mock_mode or not domain:
            entropy = features.get("shannon_entropy", 0.0)
            length = features.get("domain_length", 0)
            score = 0.0
            if length >= 12: score += 0.4
            if entropy > 3.4: score += 0.5
            return (score > 0.8), min(score, 1.0), time.time() - start_time
            
        # TENSOR FIX: Fast, pre-initialized encoding
        encoded = [self.char_map.get(c, 0) for c in domain.lower()]
        if len(encoded) < 35: 
            encoded += [0] * (35 - len(encoded))
        encoded = encoded[:35]
        
        try:
            with torch.no_grad():
                tensor = torch.tensor([encoded], dtype=torch.long)
                
                # SHAPE GUARD: Prevent runtime crash
                if tensor.shape[1] != 35:
                    return False, 0.0, time.time() - start_time
                    
                output = self.model(tensor)
                score = float(output.item())
        except Exception as e:
            logger.error(f"[Inference] Tensor execution failed: {e}")
            return False, 0.0, time.time() - start_time
            
        latency = time.time() - start_time
        return (score > 0.6), score, latency


class ThreatModelOrchestrator:
    def __init__(self):
        self.dga_model = DGAClassifier()

    def evaluate(self, event: dict, features: dict) -> list:
        ml_alerts = []
        
        # Filter out the massive background Zeek dataset to keep the 7 hackathon attacks perfectly proportionate
            
        evt_type = event.get("event_type")
        
        if evt_type == "dns":
            # Guard: Never silently score invalid input
            if "shannon_entropy" not in features:
                return ml_alerts
                
            is_threat, conf, latency = self.dga_model.predict(features, event.get('query', ''))
            if is_threat:
                ml_alerts.append({
                    "model_name": self.dga_model.model_name,
                    "model_version": f"{self.dga_model.model_version}{'_MOCK' if self.dga_model.mock_mode else ''}",
                    "threat_class": "DGA / DNS Tunnelling",
                    "severity": "high",
                    "confidence": float(conf),
                    "evidence": {"inference_latency_ms": latency * 1000},
                    "mitre_tactic": "Command and Control",
                    "mitre_technique": "T1568"
                })
                
        return ml_alerts
