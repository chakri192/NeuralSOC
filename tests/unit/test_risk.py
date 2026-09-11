"""calculate_risk_score() combines a correlated incident's alerts into
one score via log-odds pooling of each DISTINCT detector's strongest
signal -- replacing a "max severity bucket + flat points per alert"
heuristic that ignored confidence_score entirely and rewarded repeated
firings of the SAME detector as if they were independent corroborating
evidence. See inference/risk.py's own docstring for the real-world
motivation (a single ongoing DNS burst produced 224 duplicate alerts
live this session) and the real measured improvement
(scripts/evaluate_composite_scoring_against_real_data.py).
"""
import math

import pytest

from inference.risk import calculate_risk_score


def test_no_alerts_returns_zero():
    assert calculate_risk_score([]) == 0.0


def test_single_alert_score_matches_its_own_confidence():
    # Log-odds pooling of exactly one term is the identity: sigmoid(logit(p)) == p.
    score = calculate_risk_score([{"model_name": "DL_CNN_DGA", "confidence_score": 0.8}])
    assert score == pytest.approx(80.0, abs=0.5)


def test_two_distinct_detectors_score_higher_than_either_alone():
    solo = calculate_risk_score([{"model_name": "DL_CNN_DGA", "confidence_score": 0.7}])
    combined = calculate_risk_score([
        {"model_name": "DL_CNN_DGA", "confidence_score": 0.7},
        {"model_name": "RULE_DNS_QUERY_BURST", "confidence_score": 0.7},
    ])
    assert combined > solo


def test_repeated_same_detector_does_not_inflate_score():
    """Regression test for the exact bug found live this session: 224
    duplicate RULE_DNS_QUERY_BURST alerts from one ongoing DNS burst
    must score the same as a single one of them, not 224x higher."""
    single = calculate_risk_score([{"model_name": "RULE_DNS_QUERY_BURST", "confidence_score": 0.9}])
    many = calculate_risk_score([{"model_name": "RULE_DNS_QUERY_BURST", "confidence_score": 0.9}] * 224)
    assert single == many


def test_repeated_detector_uses_its_strongest_alert():
    score = calculate_risk_score([
        {"model_name": "DL_CNN_DGA", "confidence_score": 0.5},
        {"model_name": "DL_CNN_DGA", "confidence_score": 0.95},
        {"model_name": "DL_CNN_DGA", "confidence_score": 0.6},
    ])
    solo_strongest = calculate_risk_score([{"model_name": "DL_CNN_DGA", "confidence_score": 0.95}])
    assert score == solo_strongest


def test_falls_back_to_threat_class_when_no_model_name_or_rule_id():
    # Two alerts sharing a threat_class but with no model_name/rule_id
    # are treated as the SAME detector (deduplicated), matching what a
    # human would consider "the same kind of finding repeated."
    grouped = calculate_risk_score([
        {"threat_class": "Reconnaissance", "confidence_score": 0.6},
        {"threat_class": "Reconnaissance", "confidence_score": 0.8},
    ])
    solo_strongest = calculate_risk_score([{"threat_class": "Reconnaissance", "confidence_score": 0.8}])
    assert grouped == solo_strongest


def test_falls_back_to_severity_when_no_confidence_score():
    critical = calculate_risk_score([{"model_name": "X", "severity": "critical"}])
    low = calculate_risk_score([{"model_name": "X", "severity": "low"}])
    assert critical > low


def test_unknown_severity_defaults_low_does_not_raise():
    score = calculate_risk_score([{"model_name": "X", "severity": "not-a-real-severity"}])
    assert 0.0 < score < 100.0


def test_confidence_at_exact_boundaries_does_not_raise():
    # 1.0 and 0.0 would make log(c / (1 - c)) blow up (division by zero /
    # log(0)) without clamping.
    score_high = calculate_risk_score([{"model_name": "X", "confidence_score": 1.0}])
    score_low = calculate_risk_score([{"model_name": "X", "confidence_score": 0.0}])
    assert math.isfinite(score_high)
    assert math.isfinite(score_low)
    assert 0.0 <= score_high <= 100.0
    assert 0.0 <= score_low <= 100.0


def test_malformed_confidence_score_falls_back_gracefully():
    score = calculate_risk_score([{"model_name": "X", "confidence_score": "not-a-number", "severity": "high"}])
    assert 0.0 < score < 100.0


def test_score_is_bounded_zero_to_hundred_even_with_many_strong_detectors():
    alerts = [{"model_name": f"detector_{i}", "confidence_score": 0.99} for i in range(10)]
    score = calculate_risk_score(alerts)
    assert 0.0 <= score <= 100.0
