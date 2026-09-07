import os
import secrets
from datetime import datetime, timedelta, timezone
import jwt
from typing import List, Optional

JWT_SECRET = os.getenv("TSOC_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MIN = int(os.getenv("TSOC_JWT_EXPIRY_MIN", "30"))

# PyJWT only warns (InsecureKeyLengthWarning) at encode/decode time if the
# HS256 key is under the RFC 7518 SS3.2 minimum of 32 bytes -- a warning is
# easy to miss in production log noise. Fail at boot instead, the same way
# TSOC_API_KEY missing already fails at boot in api/deps.py, rather than
# letting a weak secret run silently until someone reads the logs. Only
# enforced when a secret IS configured -- an entirely unset TSOC_JWT_SECRET
# is intentionally still a lazy failure (see verify_token below): a
# deployment using only the static service key never needs one at all.
if JWT_SECRET and len(JWT_SECRET.encode("utf-8")) < 32:
    raise RuntimeError(
        f"TSOC_JWT_SECRET is {len(JWT_SECRET.encode('utf-8'))} bytes; HS256 "
        "requires >=32 bytes (RFC 7518 Section 3.2). Generate one with: "
        "openssl rand -hex 32"
    )


def create_token(
    scopes: List[str],
    subject: Optional[str] = None,
    tenant_id: Optional[int] = None,
    user_id: Optional[int] = None,
    purpose: Optional[str] = None,
    expiry_minutes: Optional[int] = None,
) -> str:
    """tenant_id/user_id are embedded for real per-employee sessions (the
    static service key path never sets them). purpose/expiry_minutes are
    for single-purpose, short-lived tokens that are NOT session
    credentials -- a password-reset or invite link, which must not be
    usable as a general-purpose API token just because it's a valid JWT
    (api/routes/auth.py checks payload["purpose"] before honoring one).
    jti lets api/deps.py's revocation denylist revoke one specific token
    (logout, or a reset/invite link consumed once) without needing to
    rotate TSOC_JWT_SECRET and invalidate every other session fleet-wide.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject or "tsoc-service",
        "scopes": scopes,
        "iat": now,
        "exp": now + timedelta(minutes=expiry_minutes if expiry_minutes is not None else JWT_EXPIRY_MIN),
        "jti": secrets.token_hex(16),
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    if user_id is not None:
        payload["user_id"] = user_id
    if purpose is not None:
        payload["purpose"] = purpose
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Decode and verify a JWT. Raises JWTError (bad signature/expired/
    malformed) or RuntimeError (secret not configured) rather than
    returning {} on failure — a caller that only checks truthiness of the
    scopes list must not be able to mistake "invalid token" for "valid
    token with no scopes"."""
    if not JWT_SECRET:
        raise RuntimeError("TSOC_JWT_SECRET not configured")
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
