import math

# A detection without a confidence_score (defensive fallback only --
# every real detector in inference/rules.py and inference/stream_processor_faust.py
# sets one) falls back to a severity-implied confidence rather than a
# flat bucket score, so it still participates correctly in the log-odds
# combination below.
_SEVERITY_TO_CONFIDENCE = {"critical": 0.97, "high": 0.9, "medium": 0.75, "low": 0.55}


def calculate_risk_score(alerts: list) -> float:
    """Aggregated risk score for one incident's worth of correlated
    alerts (inference/correlation.py's IncidentCorrelator.add_alert()).

    Combines each DISTINCT detector's strongest signal via log-odds
    pooling (equivalent to a naive-Bayes independent-evidence
    combination) rather than the previous "max severity bucket + 5 flat
    points per additional alert" heuristic, which had two real problems,
    both found by actually running detectors against real attack data
    (see SECURITY.md's "Composite incident scoring" section):

    1. It ignored each alert's own confidence_score entirely -- a
       DL_CNN_DGA hit at 0.51 and one at 0.99 both just mapped to
       "high" severity's flat 75 points.
    2. It rewarded raw alert *volume* linearly, regardless of whether
       the volume came from several genuinely different, corroborating
       detectors (real evidence something is wrong) or the same
       detector re-firing many times on one ongoing pattern (observed
       live this session: 224 duplicate RULE_DNS_QUERY_BURST alerts from
       a single infected host's one ongoing DNS burst, which would have
       inflated risk 224x under the old scheme for what is, underneath,
       one corroborating signal, not 224).

    Log-odds pooling fixes both: repeated firings of the SAME detector
    (grouped by model_name/rule_id) are deduplicated to that detector's
    single strongest alert -- correlated observations, not independent
    evidence -- while genuinely distinct detectors agreeing combine into
    a stronger joint estimate than any one alone. Measured directly
    against real CTU-13 flows
    (scripts/evaluate_composite_scoring_against_real_data.py): combining
    the flow autoencoder with the rule-based detectors this way catches
    53.7% of real botnet flows, against 36.9% for the single best
    detector alone across the same 13 real scenarios.
    """
    if not alerts:
        return 0.0

    best_confidence_by_detector = {}
    for a in alerts:
        detector = a.get("model_name") or a.get("rule_id") or a.get("threat_class") or "unknown"
        conf = a.get("confidence_score", a.get("confidence"))
        if conf is None:
            conf = _SEVERITY_TO_CONFIDENCE.get(str(a.get("severity", "low")).lower(), 0.55)
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.55
        # Clamp away from the exact 0/1 boundary: log-odds is undefined
        # there, and a single detector's real-world confidence is never
        # actually certain enough to justify an infinite log-odds term.
        conf = min(max(conf, 0.01), 0.99)
        if detector not in best_confidence_by_detector or conf > best_confidence_by_detector[detector]:
            best_confidence_by_detector[detector] = conf

    log_odds_sum = sum(math.log(c / (1.0 - c)) for c in best_confidence_by_detector.values())
    combined_probability = 1.0 / (1.0 + math.exp(-log_odds_sum))

    return round(combined_probability * 100.0, 2)
