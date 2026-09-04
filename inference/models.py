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
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class DeepLearningEngine:
    def _load_model_from_disk(self) -> Tuple[torch.jit.ScriptModule, str]:
        """Loads and validates model from disk. Returns (model, sha)."""
        artifact_path = os.getenv("MODEL_PATH", "models/cnn_dga.pt")
        sha_path = artifact_path + ".sha256"

        # Prevent unbounded memory reads from malicious/corrupted files
        MAX_MODEL_SIZE_BYTES = int(os.getenv("MAX_MODEL_SIZE_BYTES", str(50 * 1024 * 1024)))
        if os.path.exists(artifact_path):
            file_size = os.path.getsize(artifact_path)
            if file_size > MAX_MODEL_SIZE_BYTES:
                raise RuntimeError(f"Integrity Error: Model file exceeds maximum allowed size ({file_size} > {MAX_MODEL_SIZE_BYTES})")

        with open(sha_path, 'r', encoding='utf-8') as f_sha:
            expected_sha = f_sha.read(1024).strip()  # strict full hash required; reject truncated.strip()

        with open(artifact_path, 'rb') as f_bin:
            model_bytes = f_bin.read()

        computed_sha = hashlib.sha256(model_bytes).hexdigest()
        if not secrets.compare_digest(computed_sha, expected_sha):
            raise RuntimeError(f"Integrity Error: SHA-256 mismatch (got {computed_sha}, expected {expected_sha})")

        # Load TorchScript model directly from validated in-memory buffer (B614 suppressed only for immutable startup load)
        model_buffer = io.BytesIO(model_bytes)
        model = torch.jit.load(model_buffer, map_location=torch.device('cpu'))
        model.eval()
        return model, computed_sha

    def __init__(self, start_verifier: bool = True, verify_interval: int = 60):
        self.model = None
        self._inference_count = 0
        self._inference_lock = threading.Lock()
        self._last_mtime = 0.0
        self._stop_verifier = threading.Event()

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

        if start_verifier:
            self._start_background_verifier(verify_interval)

    def _start_background_verifier(self, interval_sec: int):
        def _verifier_loop():
            while not self._stop_verifier.is_set():
                if self._stop_verifier.wait(timeout=interval_sec):
                    break
                self._recheck_integrity()
        verifier_thread = threading.Thread(target=_verifier_loop, daemon=True, name="model-integrity-verifier")
        verifier_thread.start()

    def stop_verifier(self):
        self._stop_verifier.set()

    def _recheck_integrity(self, force: bool = False) -> bool:
        """
        DISABLED: hot-reload from mutable disk files is disabled.
        Load once at startup from immutable container-image artifact.
        """
        logger.debug("Model hot-reload disabled; using startup-loaded artifact.")
        return True

    def predict(self, features: dict, domain: str = "", deadline: Optional[float] = None):
        if not domain or not self.model or not isinstance(domain, str) or len(domain) > 512:
            return False, 0.0, 0.0

        if deadline is not None and time.time() > deadline:
            logger.warning("DL inference prediction aborted: deadline already expired")
            return False, 0.0, 0.0

        try:
            # Non-blocking snapshot of model and count under brief lock; NO disk IO here.
            with self._inference_lock:
                self._inference_count += 1
                current_model = self.model

            if current_model is None:
                return False, 0.0, 0.0

            # 1. Unicode normalization and cleaning
            normalized = unicodedata.normalize('NFKC', str(domain))
            clean_domain = normalized.rstrip('.').lower()
            try:
                ascii_domain = idna.encode(clean_domain, uts46=True).decode('ascii').lower()
            except (idna.core.IDNAError, UnicodeError):
                ascii_domain = clean_domain

            # 2. Resilient character sanitization (map '_' to '-' and unmapped chars to standard tokens)
            sanitized_ascii = "".join(c if c in self.char_map else "-" for c in ascii_domain)
            if not sanitized_ascii:
                return False, 0.0, 0.0

            # Check deadline before multi-segment inspection & tensor creation
            if deadline is not None and time.time() > deadline:
                logger.warning("DL inference aborted: deadline expired before tensor creation")
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

            for d in domains_to_check[:8]:
                encoded = [self.char_map.get(c, 0) for c in d]
                if not encoded:
                    continue

                # Sliding window across domain to ensure zero blind spots for long domains
                if len(encoded) > 35:
                    step = 15
                    for start in range(0, len(encoded) - 35 + 1, step):
                        all_slices.append(encoded[start:start + 35])
                        if len(all_slices) >= 32:
                            break
                    if len(all_slices) < 32 and (len(encoded) - 35) % step != 0:
                        all_slices.append(encoded[-35:])
                else:
                    all_slices.append(encoded + [0] * (35 - len(encoded)))

                if len(all_slices) >= 32:
                    break

            # Bound slices to 32 to guarantee deterministic O(1) memory and latency
            all_slices = all_slices[:32]

            if all_slices and current_model is not None:
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
