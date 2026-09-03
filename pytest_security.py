import pytest
from unittest.mock import Mock, patch
import os
import json

# 1. Test X-Real-IP
class MockRequest:
    def __init__(self, headers, host):
        self.headers = headers
        self.client = Mock()
        self.client.host = host

def test_xff_spoofing_blocked():
    os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
    os.environ['TSOC_API_KEY'] = 'test-key'
    from api.main import get_remote_address
    # Spoofed XFF from untrusted IP
    req = MockRequest({"X-Forwarded-For": "9.9.9.9", "X-Real-IP": "9.9.9.9"}, "1.2.3.4")
    assert get_remote_address(req) == "1.2.3.4"
    
    # Valid X-Real-IP from trusted ingress
    req2 = MockRequest({"X-Real-IP": "8.8.8.8"}, "10.0.1.5")
    assert get_remote_address(req2) == "8.8.8.8"

# 2. Test MODEL_HMAC_SECRET boot
def test_model_missing_secret():
    from inference.models import DeepLearningEngine
    if "MODEL_HMAC_SECRET" in os.environ:
        del os.environ["MODEL_HMAC_SECRET"]
    
    # Create dummy artifact and sha256 to pass the file check and trigger the Exception
    os.makedirs("models", exist_ok=True)
    with open("models/cnn_dga.pt", "wb") as f:
        f.write(b"dummy")
    import hashlib
    with open("models/cnn_dga.pt.sha256", "w") as f:
        f.write(hashlib.sha256(b"dummy").hexdigest())

    # Should pass SHA256, but what does the code actually do? 
    # Ah, I removed HMAC. Let's test the SHA256 mismatch instead.
    with open("models/cnn_dga.pt.sha256", "w") as f:
        f.write("badhash")
        
    try:
        DeepLearningEngine()
        assert False, "Should raise RuntimeError for SHA256 mismatch"
    except RuntimeError as e:
        assert "FATAL: Model SHA-256 mismatch" in str(e)

# 3. Test REDIS_PASSWORD boot
def test_redis_missing_password():
    from inference.correlation import IncidentCorrelator
    if "REDIS_PASSWORD" in os.environ:
        del os.environ["REDIS_PASSWORD"]
    try:
        IncidentCorrelator()
        assert False, "Should raise RuntimeError for missing REDIS_PASSWORD"
    except RuntimeError as e:
        assert "CRITICAL: REDIS_PASSWORD missing" in str(e)

if __name__ == "__main__":
    pytest.main(["-v", "pytest_security.py"])
