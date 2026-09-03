from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
security = HTTPBearer()
import os
import traceback
import logging
from fastapi import FastAPI, Request, Query, Depends
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from api.database import get_db
from api import models
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

def get_remote_address(req: Request):
    return req.client.host if req.client else "127.0.0.1"

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
Instrumentator().instrument(app).expose(app)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dashboard.tsoc.local"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=[]
)

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal Error: {traceback.format_exc()}")
    return JSONResponse(status_code=500, content={"message": "Internal Server Error"})

from typing import Optional
class AlertResponse(BaseModel):
    id: int
    alert_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    threat_class: Optional[str]
    severity: Optional[str]
    confidence_score: float
    evidence: Optional[str]
    class Config:
        orm_mode = True

@app.get("/healthz")
def healthz(): return {'status': 'ok'}

@app.get("/api/v1/alerts", response_model=List[AlertResponse])
@limiter.limit("100/minute")
def get_alerts(request: Request, cursor: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=100), db: Session = Depends(get_db), token: HTTPAuthorizationCredentials = Depends(security)):
    if cursor == 0:
        return db.query(models.Alert).order_by(models.Alert.id.desc()).limit(limit).all()
    return db.query(models.Alert).filter(models.Alert.id < cursor).order_by(models.Alert.id.desc()).limit(limit).all()
