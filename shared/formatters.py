"""
Standardized formatters to enforce strict visual consistency for timestamps, null values, and evidence categorization.
"""
import dateutil.parser

def format_timestamp(iso_str: str) -> str:
    """Consistently formats ISO-8601 strings into readable UTC."""
    if not iso_str:
        return "Unknown Time"
    try:
        dt = dateutil.parser.isoparse(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Invalid Time"

def format_mitre(tactic: str, technique: str) -> str:
    """Formats MITRE ATT&CK labels."""
    if not tactic and not technique:
        return "Unmapped"
    if not technique:
        return tactic
    return f"{tactic} ({technique})"

def categorize_evidence(evidence: dict) -> tuple:
    """
    Separates evidence into strictly 'Observed' facts vs 'Inferred' model scores.
    Returns (observed_dict, inferred_dict, unknown_dict)
    """
    observed = {}
    inferred = {}
    unknown = {}
    
    if not isinstance(evidence, dict):
        return observed, inferred, unknown
        
    for k, v in evidence.items():
        if v is None or v == "" or v == "unknown":
            unknown[k] = v
        # Any heuristic score, ML latency, or entropy is an inference/calculated metric
        elif any(term in k.lower() for term in ["score", "ml_", "entropy", "confidence", "latency"]):
            inferred[k] = v
        else:
            observed[k] = v
            
    return observed, inferred, unknown
