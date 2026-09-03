def calculate_risk_score(alerts: list) -> float:
    """
    Calculates an aggregated risk score based on the severity and volume of alerts.
    Implements a simple logarithmic escalation to prevent unbounded scores.
    """
    if not alerts:
        return 0.0

    severity_weights = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0
    }
    
    base_score = max([severity_weights.get(a.get("severity", "low").lower(), 10.0) for a in alerts])
    
    # Add a small penalty for volume (e.g., 5 points per additional alert)
    volume_penalty = (len(alerts) - 1) * 5.0
    
    total_risk = base_score + volume_penalty
    
    # Cap maximum risk score at 100.0
    return min(total_risk, 100.0)
