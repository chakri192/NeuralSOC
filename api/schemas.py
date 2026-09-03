from pydantic import BaseModel
from typing import Optional

class AlertResponse(BaseModel):
    id: int
    alert_id: str
    timestamp: str
    event_type: str
    threat_class: str
    confidence_score: float
    severity: str
    source_ip: str
    destination_ip: str
    evidence: Optional[str] = None

    class Config:
        from_attributes = True

class StatsResponse(BaseModel):
    total_alerts: int
    critical: int
    high: int
    medium: int
