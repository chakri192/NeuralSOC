"""inference/rules.py's JA4 fingerprint list used to be a module-level
frozenset built once at import from JA4_MALICIOUS_FINGERPRINTS -- updating
the feed meant restarting the whole stream processor. It's now reloaded on
a TTL (JA4_RELOAD_INTERVAL_SEC). These tests drive the cache directly
rather than through evaluate_rules(), and always restore its state
afterward so no test order dependency leaks into the rest of the suite.
"""
import inference.rules as rules


def _reset_ja4_cache():
    rules._ja4_cache["fingerprints"] = frozenset()
    rules._ja4_cache["loaded_at"] = 0.0


def test_ja4_fingerprints_reload_after_ttl_expires(monkeypatch):
    _reset_ja4_cache()
    try:
        monkeypatch.setenv("JA4_MALICIOUS_FINGERPRINTS", "abc123")
        first = rules._get_malicious_ja4_fingerprints()
        assert first == frozenset({"abc123"})

        # Still within the TTL: env change is not picked up yet.
        monkeypatch.setenv("JA4_MALICIOUS_FINGERPRINTS", "def456")
        assert rules._get_malicious_ja4_fingerprints() == frozenset({"abc123"})

        # Force the cache to look stale -- same effect as the TTL elapsing.
        rules._ja4_cache["loaded_at"] = 0.0
        assert rules._get_malicious_ja4_fingerprints() == frozenset({"def456"})
    finally:
        _reset_ja4_cache()


def test_ja4_fingerprints_cached_within_ttl(monkeypatch):
    _reset_ja4_cache()
    try:
        monkeypatch.setenv("JA4_RELOAD_INTERVAL_SEC", "9999")
        monkeypatch.setattr(rules, "_JA4_RELOAD_INTERVAL_SEC", 9999.0)
        monkeypatch.setenv("JA4_MALICIOUS_FINGERPRINTS", "first_value")
        rules._get_malicious_ja4_fingerprints()

        monkeypatch.setenv("JA4_MALICIOUS_FINGERPRINTS", "second_value")
        # Well within the (patched) 9999s TTL -- must still see the cached value.
        assert rules._get_malicious_ja4_fingerprints() == frozenset({"first_value"})
    finally:
        _reset_ja4_cache()


def test_evaluate_rules_still_uses_the_live_ja4_cache(monkeypatch):
    _reset_ja4_cache()
    try:
        monkeypatch.setenv("JA4_MALICIOUS_FINGERPRINTS", "custom_fp_value")
        event = {"event_type": "conn", "ja4": "custom_fp_value"}
        alerts = rules.evaluate_rules(event, {})
        assert [a["rule_id"] for a in alerts] == ["RULE_TLS_JA4_MALWARE"]

        benign_event = {"event_type": "conn", "ja4": "t13d000000_rare_fingerprint"}
        alerts = rules.evaluate_rules(benign_event, {})
        assert alerts == []
    finally:
        _reset_ja4_cache()
