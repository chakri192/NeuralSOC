import ipaddress

from jsonschema import validate, ValidationError, FormatChecker

# A regex-based IP check previously lived here. Verified against it
# directly: it accepted leading-zero octets ("01.02.03.04") that Python's
# ipaddress module (used downstream by inference/correlation.py to key
# Redis state) rejects since Python 3.9.5 -- so such an alert passed this
# schema, published, and then silently vanished from correlation with only
# a debug-level warning. Backing both the schema and the correlator with
# the SAME ipaddress-based check means they can never again disagree on
# what a valid IP is.
_format_checker = FormatChecker()


@_format_checker.checks("ip-address", raises=ValueError)
def _check_ip_address(value):
    if not isinstance(value, str):
        return True  # let the schema's own "type" keyword handle this
    ipaddress.ip_address(value)
    return True


_IP_SCHEMA = {"type": "string", "format": "ip-address"}

ALERT_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string", "format": "date-time"},
        "alert_id": {"type": "string"},
        "flow_id": {"type": ["string", "null"]},
        "trace_id": {"type": ["string", "null"]},
        "span_id": {"type": ["string", "null"]},
        "event_type": {"type": "string"},
        "threat_class": {"type": "string"},
        "confidence_score": {"type": "number"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "mitre_tactic": {"type": ["string", "null"]},
        "mitre_technique": {"type": ["string", "null"]},
        "source_ip": _IP_SCHEMA,
        "destination_ip": {
            "anyOf": [
                {"type": "null"},
                _IP_SCHEMA
            ]
        },
        "evidence": {"type": ["object", "null"]},
        "model_name": {"type": "string"},
        "model_version": {"type": "string"},
        "schema_version": {"type": "string", "enum": ["1.0"]},
        # Previously omitted under additionalProperties: False, which made
        # a documented field (stream_processor_faust.py stamps this onto
        # DLQ replay payloads; correlation.py reads it to bypass dedup)
        # structurally impossible to validate -- every replayed alert
        # failed validation and was re-queued forever.
        "is_replay": {"type": "boolean"}
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
        # format_checker=_format_checker is required for jsonschema to
        # enforce ANY declared "format" keyword at all (date-time and
        # ip-address above) -- without it, format is silently decorative,
        # which is how a non-date "timestamp" and an invalid IP previously
        # passed validation unnoticed.
        validate(instance=alert_dict, schema=ALERT_SCHEMA, format_checker=_format_checker)
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
