"""api/deps.py's get_tenant_aware_key(): the rate-limit key for
alerts/stats/triage routes. Without it, IP-based limiting alone lets one
noisy or abusive tenant's employees exhaust a rate-limit budget shared
with every other tenant whose employees happen to request from the same
IP range.
"""
from unittest.mock import MagicMock

from api.auth import create_token
from api.deps import get_tenant_aware_key


def _request(headers: dict, client_ip: str = "203.0.113.5") -> MagicMock:
    req = MagicMock()
    req.headers = headers
    req.client.host = client_ip
    return req


def test_a_valid_employee_jwt_keys_by_tenant_id():
    token = create_token(scopes=["alerts:read"], subject="42", tenant_id=7, user_id=42)
    req = _request({"Authorization": f"Bearer {token}"})
    assert get_tenant_aware_key(req) == "tenant:7"


def test_two_different_tenants_get_different_keys():
    token_a = create_token(scopes=["alerts:read"], subject="1", tenant_id=1, user_id=1)
    token_b = create_token(scopes=["alerts:read"], subject="2", tenant_id=2, user_id=2)
    key_a = get_tenant_aware_key(_request({"Authorization": f"Bearer {token_a}"}))
    key_b = get_tenant_aware_key(_request({"Authorization": f"Bearer {token_b}"}))
    assert key_a != key_b


def test_the_static_service_key_has_no_tenant_id_and_falls_back_to_ip(monkeypatch):
    import api.deps as deps

    monkeypatch.setattr(deps, "API_KEY", "the-static-key")
    req = _request({"Authorization": "Bearer the-static-key"}, client_ip="198.51.100.9")
    # The static key isn't a JWT at all -- verify_token() raises, falling
    # through to the same IP-based key every other unauthenticated or
    # non-tenant caller gets.
    assert get_tenant_aware_key(req) == "198.51.100.9"


def test_a_malformed_token_falls_back_to_ip():
    req = _request({"Authorization": "Bearer not-a-real-jwt"}, client_ip="198.51.100.9")
    assert get_tenant_aware_key(req) == "198.51.100.9"


def test_no_auth_header_falls_back_to_ip():
    req = _request({}, client_ip="198.51.100.9")
    assert get_tenant_aware_key(req) == "198.51.100.9"
