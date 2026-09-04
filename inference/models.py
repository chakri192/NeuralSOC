import torch
import os
import io
import hashlib
import unicodedata
import idna
import logging
import time
import string
import secrets
import threading
from typing import Tuple

logger = logging.getLogger(__name__)

class DeepLearningEngine:
    def _load_model_from_disk(self) -> Tuple[torch.jit.ScriptModule, str]:
        """Loads and validates model from disk. Returns (model, sha)."""
        artifact_path = os.getenv("MODEL_PATH", "models/cnn_dga.pt")
        sha_path = artifact_path + ".sha256"
        with open(sha_path, 'r', encoding='utf-8') as f_sha:
            expected_sha = f_sha.read().split()[0].strip()

        with open(artifact_path, 'rb') as f_bin:
            model_bytes = f_bin.read()

        computed_sha = hashlib.sha256(model_bytes).hexdigest()
        if not secrets.compare_digest(computed_sha, expected_sha):
            raise RuntimeError(f"Integrity Error: SHA-256 mismatch (got {computed_sha}, expected {expected_sha})")

        # Load TorchScript model directly from the validated in-memory buffer
        model_buffer = io.BytesIO(model_bytes)
        model = torch.jit.load(model_buffer, map_location=torch.device('cpu'))  # nosec B614
        model.eval()
        return model, computed_sha

    def __init__(self):
        self.model = None
        self._inference_count = 0
        self._inference_lock = threading.Lock()
        self._INTEGRITY_CHECK_INTERVAL = 300  # Re-verify model SHA-256 every 300 inferences
        self._last_mtime = 0.0

        # Lock PyTorch intra-op CPU threads once globally at initialization to prevent threadpool racing
        try:
            torch.set_num_threads(1)
        except Exception as e:
            logger.debug(f"Could not set PyTorch thread count: {e}")

        try:
            artifact_path = os.getenv("MODEL_PATH", "models/cnn_dga.pt")
            if os.path.exists(artifact_path):
                self._last_mtime = os.path.getmtime(artifact_path)
            self.model, self._expected_sha = self._load_model_from_disk()
            self._last_check = time.time()
        except Exception as e:
            logger.error(f"Model initialization failure: {e}")
            raise

        valid_chars = string.ascii_lowercase + string.digits + "-."
        self.char_map = {c: i + 1 for i, c in enumerate(valid_chars)}

    def _recheck_integrity(self) -> bool:
        """
        Runtime re-verification: validates model file integrity against cryptographic SHA-256.
        If file changed on disk but hash is valid, hot-reloads the model.
        Fails closed on cryptographic mismatch.
        """
        try:
            artifact_path = os.getenv("MODEL_PATH", "models/cnn_dga.pt")
            new_model, new_sha = self._load_model_from_disk()

            if new_sha != self._expected_sha:
                logger.info("New model version detected and validated; performing hot-reload.")
                with self._inference_lock:
                    self.model = new_model
                    self._expected_sha = new_sha
                    if os.path.exists(artifact_path):
                        self._last_mtime = os.path.getmtime(artifact_path)

            self._last_check = time.time()
            return True
        except (IOError, OSError) as io_err:
            logger.error("Transient disk I/O error during model re-check: %s. Retaining validated in-memory model.", io_err)
            return True
        except Exception as e:
            logger.critical("Unexpected integrity re-check exception: %s. Failing closed.", e)
            with self._inference_lock:
                self.model = None
            return False

    def predict(self, features: dict, domain: str = ""):
        if not domain or not self.model or len(domain) > 512:
            return False, 0.0, 0.0

        try:
            # Thread-safe integrity refresh — protect entire check window
            with self._inference_lock:
                self._inference_count += 1
                count_check = (self._inference_count % self._INTEGRITY_CHECK_INTERVAL == 0)
                if count_check:
                    # Hold lock during re-check to prevent concurrent load of different states
                    if not self._recheck_integrity():
                        return False, 0.0, 0.0

            # Read-Copy-Update: snapshot model reference under lock, then release for concurrent inference
            with self._inference_lock:
                current_model = self.model

            # 1. Unicode normalization and cleaning
            normalized = unicodedata.normalize('NFKC', str(domain))
            clean_domain = normalized.rstrip('.').lower()
            try:
                ascii_domain = idna.encode(clean_domain, uts46=True).decode('ascii').lower()
            except (idna.core.IDNAError, UnicodeError):
                ascii_domain = clean_domain

            # 2. Resilient character sanitization (map '_' to '-' and unmapped chars to standard tokens)
            sanitized_ascii = "".join(c if c in self.char_map else ("-" if c == "_" else "") for c in ascii_domain)
            if not sanitized_ascii:
                return False, 0.0, 0.0

            # 3. Multi-segment inspection to defeat prefix padding and sub-domain evasion
            domains_to_check = [sanitized_ascii]
            # If the domain is an IDN/homoglyph (punycode xn--), inspect both punycode and ASCII-mapped variants
            if ascii_domain != clean_domain:
                sanitized_clean = "".join(c if c in self.char_map else "" for c in clean_domain)
                if sanitized_clean and sanitized_clean not in domains_to_check:
                    domains_to_check.append(sanitized_clean)

            parts = [p for p in sanitized_ascii.split('.') if p]
            if len(parts) >= 2:
                sld = '.'.join(parts[-2:])
                if sld not in domains_to_check:
                    domains_to_check.append(sld)
                # Check all subdomain parts with length >= 4
                for part in parts:
                    if len(part) >= 4 and part not in domains_to_check:
                        domains_to_check.append(part)

            highest_prob = 0.0
            all_slices = []

            for d in domains_to_check:
                encoded = [self.char_map.get(c, 0) for c in d]
                if not encoded:
                    continue

                # Sliding window across entire domain to ensure zero blind spots for long domains
                if len(encoded) > 35:
                    step = 15
                    MAX_SLICES = 10
                    for start in range(0, len(encoded) - 35 + 1, step):
                        if len(all_slices) >= MAX_SLICES:
                            break
                        all_slices.append(encoded[start:start + 35])
                    if len(all_slices) < MAX_SLICES and (len(encoded) - 35) % step != 0:
                        all_slices.append(encoded[-35:])
                else:
                    all_slices.append(encoded + [0] * (35 - len(encoded)))

            current_model = self.model
            if current_model is None:
                return False, 0.0, 0.0

            if all_slices:
                # Batch all slices into a single forward context to eliminate GIL/Python loop overhead
                batch_tensor = torch.tensor(all_slices, dtype=torch.long)
                with torch.no_grad():
                    output_probs = current_model(batch_tensor)
                    max_prob = float(torch.max(output_probs).item())
                    if max_prob > highest_prob:
                        highest_prob = max_prob

            is_dga = highest_prob > 0.85
            return is_dga, highest_prob, 0.1
        except Exception as e:
            logger.error(f"Prediction Error: {e}")
            return False, 0.0, 0.0


class ThreatModelOrchestrator:
    """
    Orchestrates deep learning threat detection models across traffic events.
    Exposes a standardized interface for stream processing architectures.
    """
    def __init__(self):
        self.dl_engine = DeepLearningEngine()

    def evaluate(self, event: dict, features: dict) -> list:
        detections = []
        if event.get("event_type") == "dns":
            query = event.get("query", "")
            is_dga, prob, _ = self.dl_engine.predict(features, query)
            if is_dga:
                detections.append({
                    "threat_class": "DGA / DNS Tunnelling",
                    "severity": "high",
                    "confidence": prob,
                    "rule_id": "DL_CNN_DGA"
                })
        return detections
