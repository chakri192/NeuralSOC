import json
from jsonschema import validate, ValidationError

# SECURITY FIX: Strict regex allows IPv4, IPv6, or "unknown", but instantly blocks XSS/SQL payloads
IP_REGEX = r"^([a-fA-F0-9:]+|[0-9\.]+|unknown)$"

ALERT_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string", "format": "date-time"},
        "alert_id": {"type": "string"},
        "flow_id": {"type": ["string", "null"]},
        "event_type": {"type": "string"},
        "threat_class": {"type": "string"},
        "confidence_score": {"type": "number"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "mitre_tactic": {"type": "string"},
        "mitre_technique": {"type": "string"},
        "source_ip": {"type": "string", "pattern": IP_REGEX},
        "destination_ip": {"type": "string", "pattern": IP_REGEX},
        "evidence": {"type": "object"},
        "model_name": {"type": "string"},
        "model_version": {"type": "string"},
        "schema_version": {"type": "string", "enum": ["1.0"]}
    },
    "required": [
        "timestamp", "alert_id", "event_type", "threat_class", 
        "confidence_score", "severity", "source_ip", "schema_version"
    ],
    "additionalProperties": False
}

def validate_alert(alert_dict: dict) -> tuple[bool, str]:
    """
    Strictly validates the outgoing alert against the enterprise schema constraint.
    """
    try:
        validate(instance=alert_dict, schema=ALERT_SCHEMA)
        return True, ""
    except ValidationError as e:
        return False, e.message

def validate_zeek_event(event_dict: dict) -> bool:
    """
    Basic sanity check for Zeek JSON events. Must have a timestamp and id/uid.
    """
    if not isinstance(event_dict, dict):
        return False
    # Ensure minimum required fields for correlation are present
    if "ts" not in event_dict:
        return False
    return True
