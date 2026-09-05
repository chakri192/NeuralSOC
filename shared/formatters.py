"""
Standardized formatters to enforce strict visual consistency for timestamps, null values, and evidence categorization.
"""
import re
import dateutil.parser

_MARKDOWN_SPECIAL_CHARS = re.compile(r'([\\`*_{}\[\]()#+\-.!|>~])')


def escape_markdown(value) -> str:
    """Escapes CommonMark/Streamlit markdown metacharacters in a value
    before it's interpolated into st.markdown(). Network evidence (a DNS
    query string, a JA4 fingerprint) is attacker-influenced -- anyone who
    can cause a query on the monitored network controls it -- and without
    this, a crafted value can break out of the surrounding backticks and
    render as a clickable link or trigger an outbound image fetch the
    instant an analyst opens the incident. Escaping doesn't change how
    ordinary values render: CommonMark consumes the backslash and shows
    the literal character, so "10.0.0.1" still displays as "10.0.0.1"."""
    return _MARKDOWN_SPECIAL_CHARS.sub(r'\\\1', str(value))

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
