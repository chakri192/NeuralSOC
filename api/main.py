from fastapi import FastAPI, Depends, Security, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from api.database import SessionLocal, engine, Base
from api import models
import logging

from fastapi.security.api_key import APIKeyHeader

logger = logging.getLogger("api")

API_KEY = "tsoc-prod-key-2026"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key. Access Denied."
    )

Base.metadata.create_all(bind=engine)

app = FastAPI(title="T-SOC API", description="Enterprise SOC Backend")

# 1. SECURITY FIX: Global Exception Handler to prevent Stack Trace Leakage
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"[API Crash Guard] Unhandled exception on {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": "An unexpected error occurred. Please contact the SOC administrator."}
    )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 2. PERFORMANCE FIX: Strict Pydantic Query Bounds to prevent Database OOM crashes
@app.get("/api/v1/alerts")
def get_alerts(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    alerts = db.query(models.Alert).order_by(models.Alert.id.desc()).limit(limit).all()
    return alerts

@app.get("/api/v1/stats")
def get_stats(db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    total = db.query(models.Alert).count()
    critical = db.query(models.Alert).filter(models.Alert.severity == "critical").count()
    high = db.query(models.Alert).filter(models.Alert.severity == "high").count()
    medium = db.query(models.Alert).filter(models.Alert.severity == "medium").count()
    
    return {
        "total_alerts": total, 
        "critical": critical, 
        "high": high,
        "medium": medium
    }
