from sqlalchemy import Column, Integer, String, Float, Text
from api.database import Base

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(String, index=True)
    event_type = Column(String)
    
    # PERFORMANCE FIX: Added index=True to prevent Full Table Scans on dashboard stats
    threat_class = Column(String, index=True)
    confidence_score = Column(Float)
    severity = Column(String, index=True)
    
    source_ip = Column(String)
    destination_ip = Column(String)
    evidence = Column(Text) # JSON string representation
    trace_id = Column(String, index=True, nullable=True)
