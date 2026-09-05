from typing import Optional

from pydantic import BaseModel, ConfigDict


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    timestamp: str
    event_type: str
    threat_class: Optional[str] = None
    severity: Optional[str] = None
    confidence_score: Optional[float] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    evidence: Optional[str] = None
    trace_id: Optional[str] = None
    flow_id: Optional[str] = None
    span_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    schema_version: Optional[str] = None


class StatsResponse(BaseModel):
    total_alerts: int
    critical: int
    high: int
    medium: int
    low: int


class AlertPayload(BaseModel):
    """Validated shape for an inbound Kafka alert message, mirroring
    inference/schemas.py's ALERT_SCHEMA. api/kafka_sink.py constructs the
    ORM object from this model's fields only, so an attacker-influenced
    Kafka payload can never set the primary key or a SQLAlchemy internal
    attribute name (previously possible via unrestricted **kwargs)."""

    alert_id: str
    event_type: str
    timestamp: str
    threat_class: str
    severity: str
    confidence_score: float
    source_ip: str

    destination_ip: Optional[str] = None
    evidence: Optional[str] = None
    trace_id: Optional[str] = None
    flow_id: Optional[str] = None
    span_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    schema_version: Optional[str] = None
