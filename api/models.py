from sqlalchemy import Column, Integer, String, Float, Text
from api.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True, nullable=False)
    timestamp = Column(String, index=True, nullable=False)
    event_type = Column(String, nullable=False)

    # PERFORMANCE FIX: Added index=True to prevent Full Table Scans on dashboard stats
    threat_class = Column(String, index=True)
    confidence_score = Column(Float)
    severity = Column(String, index=True)

    source_ip = Column(String)
    destination_ip = Column(String)
    evidence = Column(Text) # JSON string representation
    trace_id = Column(String, index=True, nullable=True)

    # Rest of the canonical alert schema (inference/schemas.py ALERT_SCHEMA).
    # These were previously silently dropped by the Kafka sink's field
    # whitelist even though the pipeline always produces them — that's the
    # real cause of the dashboard's Investigate/Incidents pages crashing on
    # a missing flow_id / model_name, not just a missing default.
    flow_id = Column(String, index=True, nullable=True)
    span_id = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    model_name = Column(String, nullable=True)
    model_version = Column(String, nullable=True)
    schema_version = Column(String, nullable=True)
