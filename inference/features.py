import collections
import math

def safe_float(val) -> float:
    """Defensively parses floats, safely converting Zeek '-' nulls to 0.0"""
    if val == "-" or val is None or val == "":
        return 0.0
    try:
        return float(val)
    except ValueError:
        return 0.0

def safe_int(val) -> int:
    """Defensively parses ints, safely converting Zeek '-' nulls to 0"""
    if val == "-" or val is None or val == "":
        return 0
    try:
        return int(val)
    except ValueError:
        return 0

def shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def extract_dns_features(event: dict) -> dict:
    query = event.get("query", "")
    if not query:
        return {}
    
    length = len(query)
    digit_count = sum(c.isdigit() for c in query)
    
    return {
        "domain_length": length,
        "shannon_entropy": shannon_entropy(query),
        "digit_ratio": digit_count / length if length > 0 else 0.0
    }

def extract_flow_features(event: dict) -> dict:
    # DATA FIX: Use defensive casting to prevent Zeek '-' ValueError crashes
    duration = safe_float(event.get("duration"))
    orig_bytes = safe_int(event.get("orig_bytes"))
    resp_bytes = safe_int(event.get("resp_bytes"))
    
    return {
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "bytes_per_sec": (orig_bytes + resp_bytes) / duration if duration > 0 else 0.0
    }

def extract_features(event: dict) -> dict:
    """Safe, testable feature extraction router."""
    features = {}
    evt_type = event.get("event_type")
    
    if evt_type == "dns":
        features.update(extract_dns_features(event))
    elif evt_type == "conn":
        features.update(extract_flow_features(event))
        
    return features
