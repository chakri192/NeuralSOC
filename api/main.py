import os
import traceback
import logging
import ipaddress
import secrets
import uuid
import urllib.parse
from typing import List, Optional

from fastapi import FastAPI, Request, Query, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, text, select
from sqlalchemy.orm import defer, load_only
from pydantic import BaseModel, ConfigDict
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.database import get_db, Base, engine, SessionLocal
from api import models

API_KEY = os.getenv("TSOC_API_KEY")
if not API_KEY:
    raise RuntimeError("CRITICAL: TSOC_API_KEY must be configured.")

Base.metadata.create_all(bind=engine)

logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

# Configurable trusted proxy CIDRs (defaults to loopback and standard K8s ingress subnet)
_trusted_proxies_raw = os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
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

def _validate_ip(ip_str: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return str(addr)
    except ValueError:
        return None

def get_remote_address(request: Request) -> str:
    # Strict: never trust X-Forwarded-For / X-Real-IP unless immediate peer is verified proxy
    raw_client = request.client.host if request.client else "127.0.0.1"
    client_ip = _validate_ip(raw_client) or "127.0.0.1"
    # Only inspect proxy headers when the TCP peer is explicitly from trusted proxy list
    if _is_trusted_proxy(client_ip):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Parse right-to-left: find the first non-trusted proxy IP
            ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
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

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_SSL = os.getenv("REDIS_SSL", "false").lower() in ("true", "1", "yes")

_scheme = "rediss" if REDIS_SSL else "redis"
_auth = f":{urllib.parse.quote_plus(REDIS_PASSWORD)}@" if REDIS_PASSWORD else ""
REDIS_STORAGE_URI = os.getenv("LIMITER_STORAGE_URI", f"{_scheme}://{_auth}{REDIS_HOST}:{REDIS_PORT}/1")

try:
    # Fail-closed rate limiter: do NOT swallow errors. If Redis is unreachable,
    # reject requests or engage local fallback with explicit failure logging.
    # fail_on_first_breach=True ensures instant enforcement on rate violation.
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=REDIS_STORAGE_URI,
        swallow_errors=False,
        fail_on_first_breach=True
    )
except Exception as ex:
    logger.error("CRITICAL: Redis rate limiter initialization failed: %s; using strict in-memory fail-closed limiter", ex)
    limiter = Limiter(key_func=get_remote_address, swallow_errors=False, fail_on_first_breach=True)

_enable_docs = os.getenv("ENABLE_DOCS", "false").lower() in ("true", "1", "yes")
app = FastAPI(
    title="T-SOC Threat Detection API",
    docs_url="/docs" if _enable_docs else None,
    redoc_url="/redoc" if _enable_docs else None,
    openapi_url="/openapi.json" if _enable_docs else None
)

Instrumentator().instrument(app).expose(app)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins_env = os.getenv("CORS_ALLOWED_ORIGINS", "https://dashboard.tsoc.local")
allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID", "traceparent"],
    expose_headers=["X-Request-ID"]
)

@app.middleware("http")
async def request_tracing_middleware(request: Request, call_next):
    # W3C Trace Context & Correlation ID support
    req_id = (
        request.headers.get("X-Request-ID")
        or request.headers.get("X-Correlation-ID")
        or f"req-{uuid.uuid4().hex[:16]}"
    )
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # Do NOT leak internal Pydantic schema / field names to attacker
    return JSONResponse(status_code=422, content={"detail": "Invalid request format"})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid request format"})
    logger.error("Internal Error: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"message": "Internal Server Error"})

security_bearer = HTTPBearer(auto_error=False)

def verify_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> str:
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif request.headers.get("X-API-Key"):
        token = request.headers.get("X-API-Key")
    elif request.headers.get("Authorization"):
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
        else:
            token = auth_hdr.strip()

    if not token or not API_KEY or not secrets.compare_digest(token, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key / Authorization Token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return token

def get_authenticated_db(
    _token: str = Depends(verify_auth)
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

class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    timestamp: str
    source_ip: str
    destination_ip: Optional[str] = None
    threat_class: Optional[str] = None
    severity: Optional[str] = None
    confidence_score: float
    evidence: Optional[str] = None
    trace_id: Optional[str] = None

@app.get("/livez")
def livez():
    """Shallow liveness probe: verifies the process is up and serving without dependency coupling."""
    return {'status': 'alive'}

@app.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    """Deep readiness probe: verifies downstream database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return {'status': 'ready'}
    except Exception as ex:
        logger.error(f"Readiness probe failed: {ex}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database probe failed")

@app.get("/healthz")
def healthz():
    """Shallow health probe: verifies the HTTP listener is operational without consuming DB pool connections."""
    return {'status': 'ok'}

@app.get("/api/v1/stats")
@limiter.limit("100/minute")
def get_stats(
    request: Request,
    db: Session = Depends(get_authenticated_db)
):
    counts = db.query(models.Alert.severity, func.count(models.Alert.id)).group_by(models.Alert.severity).all()
    severity_map = {str(sev).lower() if sev else "unknown": cnt for sev, cnt in counts}
    total = sum(severity_map.values())
    return {
        "total_alerts": total,
        "critical": severity_map.get("critical", 0),
        "high": severity_map.get("high", 0),
        "medium": severity_map.get("medium", 0),
        "low": severity_map.get("low", 0)
    }

@app.get("/api/v1/alerts", response_model=List[AlertResponse])
@limiter.limit("100/minute")
def get_alerts(
    request: Request,
    cursor: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_authenticated_db)
):
    query = db.query(models.Alert).options(defer(models.Alert.evidence))
    if cursor > 0:
        query = query.filter(models.Alert.id < cursor)
    return query.order_by(models.Alert.id.desc()).limit(limit).all()

@app.get("/api/v1/alerts/{alert_id}", response_model=AlertResponse)
@limiter.limit("100/minute")
def get_alert_by_id(
    request: Request,
    alert_id: str,
    db: Session = Depends(get_authenticated_db)
):
    alert = db.query(models.Alert).filter(models.Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert
