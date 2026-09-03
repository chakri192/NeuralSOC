import pytest
from shared.formatters import format_timestamp, format_mitre, categorize_evidence
from shared.schemas import AlertView

def test_format_timestamp_valid():
    ts = "2026-09-01T08:20:31.103820+00:00"
    formatted = format_timestamp(ts)
    assert formatted == "2026-09-01 08:20:31 UTC"

def test_format_timestamp_invalid():
    assert format_timestamp("invalid_time") == "Invalid Time"
    assert format_timestamp("") == "Unknown Time"

def test_format_mitre():
    assert format_mitre("Command and Control", "T1071") == "Command and Control (T1071)"
    assert format_mitre("Discovery", "") == "Discovery"
    assert format_mitre("", "") == "Unmapped"

def test_categorize_evidence():
    evidence = {
        "query": "malicious.com",
        "orig_bytes": 500,
        "shannon_entropy": 4.5,
        "ml_confidence_score": 0.9,
        "process_name": "unknown",
        "user_id": ""
    }
    
    obs, inf, unk = categorize_evidence(evidence)
    
    # Observed facts
    assert "query" in obs
    assert "orig_bytes" in obs
    
    # Inferred/Calculated facts
    assert "shannon_entropy" in inf
    assert "ml_confidence_score" in inf
    
    # Unknown/Missing facts
    assert "process_name" in unk
    assert "user_id" in unk
