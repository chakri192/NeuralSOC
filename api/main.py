from fastapi.responses import PlainTextResponse
import psutil
from fastapi import FastAPI, Query, Depends, Security, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from api.database import SessionLocal, engine, Base
from api import models, schemas
from typing import List
import logging

from fastapi.security.api_key import APIKeyHeader

logger = logging.getLogger("api")

import os
API_KEY = os.getenv("TSOC_API_KEY")
if not API_KEY:
    raise RuntimeError("TSOC_API_KEY environment variable is required")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    import secrets
    if secrets.compare_digest(api_key_header or '', API_KEY):
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized"
    )


app = FastAPI(title="T-SOC API", description="Enterprise SOC Backend")

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

def get_remote_address(req: Request):
    return req.headers.get("X-Real-IP", req.headers.get("X-Forwarded-For", req.client.host).split(",")[0].strip())
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "https://dashboard.tsoc.local").split(","), # In production restrict this
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

@app.get("/healthz")
def healthcheck():
    return {"status": "ok", "version": "1.0.0"}

@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    return f'# HELP tsoc_cpu_usage CPU Usage\n# TYPE tsoc_cpu_usage gauge\ntsoc_cpu_usage {cpu}\n# HELP tsoc_mem_usage Memory Usage\n# TYPE tsoc_mem_usage gauge\ntsoc_mem_usage {mem}\n'


# 1. SECURITY FIX: Global Exception Handler to prevent Stack Trace Leakage
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Validation Error"})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        raise exc
    logger.error(f"[API Crash Guard] Unhandled exception on {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": "An unexpected error occurred. Please contact the SOC administrator."}
    )

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

# 2. PERFORMANCE FIX: Strict Pydantic Query Bounds to prevent Database OOM crashes
@app.get("/api/v1/alerts", response_model=List[AlertResponse])
def get_alerts(skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=100), db: Session = Depends(get_db)):
    alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).offset(skip).limit(limit).all()
    return alerts

from sqlalchemy import func
@app.get("/api/v1/stats", response_model=schemas.StatsResponse)
@limiter.limit("50/second")
def get_stats(request: Request, db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    # Consolidate into a single DB round-trip
    results = db.query(
        func.count(models.Alert.id).label('total'),
        func.sum(func.case((models.Alert.severity == 'critical', 1), else_=0)).label('critical'),
        func.sum(func.case((models.Alert.severity == 'high', 1), else_=0)).label('high'),
        func.sum(func.case((models.Alert.severity == 'medium', 1), else_=0)).label('medium')
    ).first()
    
    return {
        "total_alerts": results.total or 0,
        "critical": results.critical or 0,
        "high": results.high or 0,
        "medium": results.medium or 0
    }
