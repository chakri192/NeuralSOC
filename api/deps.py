"""Shared FastAPI dependencies: trusted-proxy IP resolution, rate limiting,
authentication, and the per-request authenticated DB session.

Split out of api/main.py so api/routes/*.py can depend on the same limiter
and auth dependencies as the app itself without importing api.main (which
would create a circular import, since api.main imports the routers).
"""
import ipaddress
import logging
import os
import secrets
import ssl
import urllib.parse
from typing import Optional

import redis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError
from slowapi import Limiter
from sqlalchemy.orm import Session

from api.auth import verify_token
from api.database import SessionLocal

logger = logging.getLogger(__name__)

# --- Trusted-proxy resolution --------------------------------------------
# Configurable trusted proxy CIDRs (defaults to loopback and standard K8s ingress subnet)
_trusted_proxies_raw = os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128,10.244.0.0/16")
TRUSTED_INGRESS_NETWORKS = []
# Enforce strict allow-list; never allow 0.0.0.0/0, ::/0, or overly broad /0-/7 prefixes
for entry in _trusted_proxies_raw.split(","):
    entry = entry.strip()
    if entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            # Block overly broad networks (IPv4 < 8, IPv6 < 64) or global 0.0.0.0/0
            if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 64) or str(net) in ("0.0.0.0/0", "::/0"):
                logger.warning("Overly broad or global proxy CIDR rejected: %s (Prefix: %d)", entry, net.prefixlen)
                continue
            TRUSTED_INGRESS_NETWORKS.append(net)
        except ValueError as ex:
            logger.warning("Invalid proxy network CIDR %s: %s", entry, ex)


def _validate_ip(ip_str: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return str(addr)
    except ValueError:
        return None


def _is_trusted_proxy(ip: str) -> bool:
    # Strict allow-list only; default must not include open CIDRs
    try:
        addr = ipaddress.ip_address(ip.strip())
        for net in TRUSTED_INGRESS_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False


# A stuffed X-Forwarded-For (thousands of comma-separated junk entries)
# costs a split() + a validation call per entry -- bounded here rather
# than processing an attacker-controlled string of unbounded size. 2048
# chars / 20 hops comfortably covers any real proxy chain (20 IPv6
# addresses alone would be under 1000 chars).
_MAX_XFF_HEADER_LEN = 2048
_MAX_XFF_HOPS = 20


def get_remote_address(request: Request) -> str:
    # Strict: never trust X-Forwarded-For / X-Real-IP unless immediate peer is verified proxy
    raw_client = request.client.host if request.client else "127.0.0.1"
    client_ip = _validate_ip(raw_client) or "127.0.0.1"
    # Only inspect proxy headers when the TCP peer is explicitly from trusted proxy list
    if _is_trusted_proxy(client_ip):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded and len(forwarded) > _MAX_XFF_HEADER_LEN:
            forwarded = None
        if forwarded:
            # Parse right-to-left: find the first non-trusted proxy IP.
            # Only the last _MAX_XFF_HOPS entries are considered -- those
            # are the ones closest to our own trusted proxy, which is what
            # right-to-left parsing cares about first regardless of how
            # many (or how few) genuine hops precede them.
            ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()][-_MAX_XFF_HOPS:]
            valid_ips = []
            for ip in reversed(ips):
                valid = _validate_ip(ip)
                if valid:
                    valid_ips.append(valid)
                    if not _is_trusted_proxy(valid):
                        return valid
            # If all forwarded IPs are trusted proxies, return leftmost originating client
            # to isolate rate limit buckets and prevent shared ingress exhaustion DoS
            if valid_ips:
                return valid_ips[-1]
            return client_ip
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            valid = _validate_ip(real_ip)
            if valid:
                return valid
    return client_ip


# --- Rate limiter ----------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_SSL = os.getenv("REDIS_SSL", "true").lower() in ("true", "1", "yes")
if REDIS_SSL and not REDIS_PASSWORD:
    raise RuntimeError("REDIS_PASSWORD required when REDIS_SSL=true")

def _build_redis_storage_uri(scheme, host, port, password, ssl_enabled, ca_cert_path, client_cert_path, client_key_path):
    """Pulled out to a pure function (rather than inline module-level
    statements) so the TLS query-param construction is directly
    unit-testable without reimporting this module (which has real
    side effects at import time -- constructing the actual Limiter).

    redis-py's from_url() (what slowapi/limits use under storage_uri) has
    no way to trust a custom CA, or present a client cert for mutual TLS,
    short of URL query parameters -- without ssl_ca_certs, a self-signed
    or internal CA (inference/correlation.py already supports the same
    REDIS_CA_CERT_PATH) fails verification here even though the
    certificate itself is perfectly valid, discovered only by actually
    running this against the docker-compose redis service's self-signed
    dev cert rather than a mock.
    """
    auth = f":{urllib.parse.quote_plus(password)}@" if password else ""
    uri = f"{scheme}://{auth}{host}:{port}/1"

    if ssl_enabled:
        ssl_query_params = {}
        if ca_cert_path and os.path.exists(ca_cert_path):
            ssl_query_params["ssl_cert_reqs"] = "required"
            ssl_query_params["ssl_ca_certs"] = ca_cert_path
        # Client cert (mutual TLS): both-or-neither -- a cert with no key
        # (or vice versa) is a real misconfiguration, not a "just skip
        # it" case, so it's deliberately not silently half-applied.
        # Existence is checked (not just that the paths are non-empty)
        # because k8s/soc-deployment.yaml sets both env vars
        # unconditionally to a cert-manager-issued Secret's mount path --
        # if that Certificate hasn't actually been issued yet, the path
        # exists as a string but not as a real file, and redis-py would
        # otherwise only discover that by failing to build an SSL context
        # at connection time. Same pattern as inference/correlation.py's
        # identical handling.
        if client_cert_path and client_key_path and os.path.exists(client_cert_path) and os.path.exists(client_key_path):
            ssl_query_params["ssl_certfile"] = client_cert_path
            ssl_query_params["ssl_keyfile"] = client_key_path
        if ssl_query_params:
            uri += "?" + "&".join(f"{k}={urllib.parse.quote(v)}" for k, v in ssl_query_params.items())

    return uri


if "LIMITER_STORAGE_URI" in os.environ:
    # Preserve os.getenv(key, default)'s exact semantics: only the
    # variable's *absence* falls through to the built URI below -- an
    # explicitly-set-but-empty value must still win, unlike `or`, which
    # would treat "" as absent too.
    REDIS_STORAGE_URI = os.environ["LIMITER_STORAGE_URI"]
else:
    REDIS_STORAGE_URI = _build_redis_storage_uri(
        scheme="rediss" if REDIS_SSL else "redis",
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        ssl_enabled=REDIS_SSL,
        ca_cert_path=os.getenv("REDIS_CA_CERT_PATH"),
        client_cert_path=os.getenv("REDIS_CLIENT_CERT_PATH"),
        client_key_path=os.getenv("REDIS_CLIENT_KEY_PATH"),
    )

try:
    # Fail-closed rate limiter: do NOT swallow errors. If Redis is unreachable,
    # reject requests or engage local fallback with explicit failure logging.
    # Enforce TLS for rate-limit storage (reject unencrypted redis://)
    if REDIS_STORAGE_URI and not REDIS_STORAGE_URI.startswith("rediss://"):
        raise RuntimeError("Redis rate limiter requires TLS (rediss://) — enforce REDIS_SSL=true")
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=REDIS_STORAGE_URI,
        swallow_errors=False
    )
except BaseException as ex:
    logger.error("CRITICAL: Redis rate limiter initialization failed: %s; using strict in-memory fail-closed limiter", ex)
    limiter = Limiter(key_func=get_remote_address, swallow_errors=False)


# --- Shared Redis client (JWT revocation, login lockout) -------------------
# A real redis.Redis client, not the storage_uri string slowapi's Limiter
# builds above -- api/routes/auth.py needs plain GET/SET/EXPIRE, which the
# `limits` library's storage backend doesn't expose. Mirrors
# inference/correlation.py's IncidentCorrelator.__init__ exactly (same
# REDIS_HOST/PORT/PASSWORD/SSL/cert env vars, same mutual-TLS handling) --
# a third near-duplicate of this connection logic, kept because unifying
# it with either existing copy is a bigger refactor than this feature
# needs, not because a third copy is anyone's target state.
_redis_client: Optional["redis.Redis"] = None


def get_redis_client() -> "redis.Redis":
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    pool_kwargs = dict(
        host=REDIS_HOST,
        port=int(REDIS_PORT),
        password=REDIS_PASSWORD,
        db=0,
        decode_responses=True,
        socket_timeout=2.0,
        socket_connect_timeout=2.0,
        max_connections=20,
        retry_on_timeout=True,
        health_check_interval=30,
    )
    if REDIS_SSL:
        pool_kwargs["connection_class"] = redis.SSLConnection
        pool_kwargs["ssl_cert_reqs"] = "required"
        redis_ca_cert = os.getenv("REDIS_CA_CERT_PATH")
        if redis_ca_cert and os.path.exists(redis_ca_cert):
            pool_kwargs["ssl_ca_certs"] = redis_ca_cert
        else:
            try:
                import certifi
                pool_kwargs["ssl_ca_certs"] = certifi.where()
            except ImportError:
                paths = ssl.get_default_verify_paths()
                if paths.cafile:
                    pool_kwargs["ssl_ca_certs"] = paths.cafile
                elif paths.capath:
                    pool_kwargs["ssl_ca_path"] = paths.capath

        client_cert = os.getenv("REDIS_CLIENT_CERT_PATH")
        client_key = os.getenv("REDIS_CLIENT_KEY_PATH")
        if client_cert and client_key and os.path.exists(client_cert) and os.path.exists(client_key):
            pool_kwargs["ssl_certfile"] = client_cert
            pool_kwargs["ssl_keyfile"] = client_key

    _redis_client = redis.Redis(connection_pool=redis.ConnectionPool(**pool_kwargs))
    return _redis_client


_JTI_DENYLIST_PREFIX = "tsoc:revoked_jti:"
_LOGIN_FAIL_PREFIX = "tsoc:login_fail:"
LOGIN_LOCKOUT_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW_SEC = 900  # 15 minutes


def revoke_jti(jti: str, ttl_seconds: int) -> None:
    """Denylists one specific token (logout, or a reset/invite link that's
    just been consumed) until it would have expired anyway -- past that,
    the JWT's own exp claim makes the denylist entry redundant, so there's
    no need to keep it (or grow the key set) forever."""
    if ttl_seconds <= 0:
        return
    try:
        get_redis_client().set(f"{_JTI_DENYLIST_PREFIX}{jti}", "1", ex=ttl_seconds)
    except redis.RedisError as ex:
        logger.error("Failed to record token revocation for jti=%s: %s", jti, ex)


def is_token_revoked(jti: str) -> bool:
    """Fails OPEN (treats Redis-unreachable as 'not revoked') rather than
    closed: unlike the rate limiter above (whose whole job IS blocking
    traffic, so failing closed on it is the safe default), this is a
    defense-in-depth check layered on top of a JWT's own signature and
    expiry, which remain valid without Redis at all. Failing closed here
    would mean a transient Redis outage locks every authenticated caller
    out of the entire API, for a feature (immediate revocation of one
    already-issued token) that matters far less than baseline
    availability."""
    if not jti:
        return False
    try:
        return get_redis_client().exists(f"{_JTI_DENYLIST_PREFIX}{jti}") > 0
    except redis.RedisError as ex:
        logger.error("Token revocation check failed open (Redis unreachable): %s", ex)
        return False


def record_failed_login(email: str) -> None:
    try:
        client = get_redis_client()
        key = f"{_LOGIN_FAIL_PREFIX}{email.lower()}"
        count = client.incr(key)
        if count == 1:
            client.expire(key, LOGIN_LOCKOUT_WINDOW_SEC)
    except redis.RedisError as ex:
        logger.error("Failed to record login failure for %s: %s", email, ex)


def clear_failed_logins(email: str) -> None:
    try:
        get_redis_client().delete(f"{_LOGIN_FAIL_PREFIX}{email.lower()}")
    except redis.RedisError as ex:
        logger.error("Failed to clear login failures for %s: %s", email, ex)


def is_locked_out(email: str) -> bool:
    """Same fail-open reasoning as is_token_revoked: a Redis outage should
    degrade brute-force protection, not take down the entire login
    endpoint for every legitimate user at once."""
    try:
        count = get_redis_client().get(f"{_LOGIN_FAIL_PREFIX}{email.lower()}")
        return count is not None and int(count) >= LOGIN_LOCKOUT_MAX_ATTEMPTS
    except redis.RedisError as ex:
        logger.error("Login lockout check failed open (Redis unreachable): %s", ex)
        return False


# --- Authentication ----------------------------------------------------------
API_KEY = os.getenv("TSOC_API_KEY")
if not API_KEY:
    raise RuntimeError("CRITICAL: TSOC_API_KEY must be configured.")

security_bearer = HTTPBearer(auto_error=False)


def _extract_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    if credentials and credentials.credentials:
        return credentials.credentials
    if request.headers.get("X-API-Key"):
        return request.headers.get("X-API-Key")
    auth_hdr = request.headers.get("Authorization")
    if auth_hdr:
        if auth_hdr.lower().startswith("bearer "):
            return auth_hdr[7:].strip()
        return auth_hdr.strip()
    return None


def _constant_time_key_match(token: str) -> bool:
    """Compare as bytes so a non-ASCII header can never raise instead of
    just failing closed (Starlette decodes headers as latin-1, so any byte
    >= 0x80 previously produced a str that secrets.compare_digest rejected
    with a TypeError instead of a 401)."""
    try:
        token_bytes = token.encode("utf-8", "surrogateescape")
        key_bytes = API_KEY.encode("utf-8")
    except Exception:
        return False
    return secrets.compare_digest(token_bytes, key_bytes)


def _authenticate(token: str) -> dict:
    """Returns a principal {"sub": ..., "scopes": [...]} for any valid
    credential, or raises 401. Two credential types are accepted:

    - the static service key (TSOC_API_KEY) — used by trusted internal
      callers such as the dashboard, which has no per-user login flow of
      its own; treated as holding every scope.
    - a JWT minted by api.auth.create_token — scoped and expiring, for any
      caller that should NOT hold blanket access. Revoked fleet-wide by
      rotating TSOC_JWT_SECRET.
    """
    if API_KEY and _constant_time_key_match(token):
        return {"sub": "service-key", "scopes": ["*"]}
    try:
        payload = verify_token(token)
    except (JWTError, RuntimeError):
        payload = None
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key / Authorization Token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    if is_token_revoked(payload.get("jti")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return payload


def verify_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> dict:
    """Authenticate the caller without requiring a specific scope."""
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key / Authorization Token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return _authenticate(token)


def require_scope(required_scope: str):
    """FastAPI dependency factory: authenticate the caller AND require the
    resulting principal to hold `required_scope` (or the service key's "*").
    Use this on routes that should reject a validly-authenticated caller
    who simply wasn't issued the right scope."""

    def _dependency(principal: dict = Depends(verify_auth)) -> dict:
        scopes = principal.get("scopes") or []
        if required_scope not in scopes and "*" not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token lacks required scope: {required_scope}",
            )
        return principal

    return _dependency


def scope_to_tenant(query, principal: dict, model):
    """Filters a query to the caller's own tenant, sourced from the JWT's
    tenant_id claim -- never a request parameter, which would let a
    caller simply ask for someone else's tenant.

    The static service key (TSOC_API_KEY) has no tenant_id at all
    (`{"sub": "service-key", "scopes": ["*"]}`) -- it's the same
    trusted-internal-caller credential that predates tenants entirely,
    so it deliberately sees every tenant's data unfiltered, the same way
    it already holds every scope. A real per-employee JWT (minted by
    api/routes/auth.py's login) always carries a tenant_id and is always
    scoped down to it.
    """
    tenant_id = principal.get("tenant_id")
    if tenant_id is None:
        return query
    return query.filter(model.tenant_id == tenant_id)


def get_tenant_aware_key(request: Request) -> str:
    """Rate-limit key for tenant-authenticated routes (alerts/stats/
    triage): the caller's tenant_id when their token decodes to one,
    falling back to get_remote_address() otherwise. Passed as
    @limiter.limit(..., key_func=get_tenant_aware_key) on those routes
    specifically -- not a global change to `limiter`'s own key_func,
    which stays IP-based for /auth/* (identity isn't established yet at
    login) and /ingest/alerts (a sensor token isn't a JWT; resolving its
    tenant_id here would mean a DB lookup on every single rate-limit
    check, which the ingest endpoint's per-tenant composite-key data
    isolation already makes unnecessary for this specific concern).

    Without this, IP-based limiting alone lets one noisy or abusive
    tenant's employees exhaust a rate-limit budget shared with every
    other tenant whose employees happen to request from the same IP
    range (a corporate NAT gateway, a shared VPN egress) -- tenant_id is
    the boundary that actually matters here, not the network address.

    Only verifies the token's signature/expiry to read its tenant_id
    claim -- does not check the revocation denylist (is_token_revoked),
    since a revoked-but-still-decodable token computing a rate-limit
    bucket key grants no access on its own; the resulting request is
    still rejected by the route's own require_scope/verify_auth
    dependency exactly as before.
    """
    token = _extract_token(request, None)
    if token:
        try:
            payload = verify_token(token)
            tenant_id = payload.get("tenant_id")
            if tenant_id is not None:
                return f"tenant:{tenant_id}"
        except (JWTError, RuntimeError):
            pass
    return get_remote_address(request)


def get_authenticated_db(
    _principal: dict = Depends(verify_auth)
) -> Session:
    """
    Requires authentication BEFORE allocating a database connection.
    Prevents unauthenticated request pool exhaustion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
