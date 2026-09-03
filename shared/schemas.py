"""
Lightweight data structures for type-safe UI rendering across Web and Terminal.
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class AlertView:
    alert_id: str
    timestamp: str
    event_type: str
    threat_class: str
    severity: str
    confidence_score: float
    source_ip: str
    destination_ip: str
    mitre_tactic: str
    mitre_technique: str
    evidence: Dict[str, Any]
    model_name: str

@dataclass
class IncidentView:
    incident_id: str
    created_timestamp: str
    updated_timestamp: str
    affected_entities: List[str]
    related_alert_ids: List[str]
    threat_classes: List[str]
    risk_score: float
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    evidence_summary: str
    status: str
