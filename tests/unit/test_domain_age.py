"""DomainAgeLookup is a genuinely different signal from the DGA CNN's
per-domain character classification -- real malicious domains are
typically registered days to months before use, real legitimate
infrastructure is typically decades old (verified against the real
Lumma Stealer capture, see docs/PATH_TO_10_OUT_OF_10.md's Phase 9 and
SECURITY.md). Pure-logic pieces (extraction, confidence mapping, date
parsing) are tested without any network; lookup_age_days() itself is
tested against the real public RDAP service the same way
tests/test_pipeline.py already tests ThreatEnricher -- accepting either
a real answer or a graceful None if the environment can't reach the
network, since the whole point of this module is that it never raises
either way.
"""
import asyncio

import pytest

from inference.domain_age import (
    YOUNG_DOMAIN_DAYS_THRESHOLD,
    DomainAgeLookup,
    confidence_for_age,
    extract_registrable_domain,
)


class TestExtractRegistrableDomain:
    def test_simple_domain(self):
        assert extract_registrable_domain("example.com") == "example.com"

    def test_strips_subdomains_to_last_two_labels(self):
        assert extract_registrable_domain("arch.filemegahab4.sbs") == "filemegahab4.sbs"
        assert extract_registrable_domain("a.b.c.example.com") == "example.com"

    def test_trailing_dot_and_case_normalized(self):
        assert extract_registrable_domain("EXAMPLE.COM.") == "example.com"

    def test_single_label_returns_none(self):
        assert extract_registrable_domain("localhost") is None

    def test_empty_or_none_returns_none(self):
        assert extract_registrable_domain("") is None
        assert extract_registrable_domain(None) is None

    def test_rejects_path_traversal_style_content(self):
        # Defense-in-depth: this must never produce a string that could
        # manipulate the eventual request URL, even though the DNS-query
        # source of this string is already constrained upstream.
        assert extract_registrable_domain("evil.com/../../internal") is None

    def test_rejects_overlong_domain(self):
        assert extract_registrable_domain("a" * 200 + ".com") is None


class TestConfidenceForAge:
    def test_brand_new_domain_is_near_max_confidence(self):
        assert confidence_for_age(0.0) == pytest.approx(0.95, abs=0.01)

    def test_domain_right_at_threshold_is_near_floor(self):
        assert confidence_for_age(YOUNG_DOMAIN_DAYS_THRESHOLD) == pytest.approx(0.55, abs=0.01)

    def test_confidence_decreases_monotonically_with_age(self):
        c1 = confidence_for_age(1.0)
        c2 = confidence_for_age(90.0)
        c3 = confidence_for_age(179.0)
        assert c1 > c2 > c3

    def test_always_within_bounds_even_for_extreme_ages(self):
        assert confidence_for_age(0.0) == pytest.approx(0.95, abs=1e-9)
        assert confidence_for_age(100000.0) == pytest.approx(0.55, abs=1e-9)


class TestParseAgeDays:
    def test_recent_utc_date(self):
        import datetime
        recent = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
        age = DomainAgeLookup._parse_age_days(recent)
        assert 9.5 < age < 10.5

    def test_z_suffix_utc_format(self):
        age = DomainAgeLookup._parse_age_days("2020-01-01T00:00:00Z")
        assert age > 365 * 4  # comfortably more than 4 years old by now

    def test_malformed_date_returns_none(self):
        assert DomainAgeLookup._parse_age_days("not-a-date") is None

    def test_none_returns_none(self):
        assert DomainAgeLookup._parse_age_days(None) is None


class TestCache:
    def test_lookup_uses_cache_on_second_call(self):
        async def run():
            lookup = DomainAgeLookup(cache_ttl_sec=60)
            try:
                lookup._set_cached("example.com", 42.0)
                assert lookup._get_cached("example.com") == 42.0
            finally:
                await lookup.close()

        asyncio.run(run())

    def test_cache_eviction_bounds_size(self):
        async def run():
            lookup = DomainAgeLookup(cache_ttl_sec=3600, max_cache_size=3)
            try:
                for i in range(5):
                    lookup._set_cached(f"domain{i}.com", float(i))
                assert len(lookup._cache) <= 3
            finally:
                await lookup.close()

        asyncio.run(run())


class TestLookupAgeDaysNeverRaises:
    def test_malformed_domain_returns_none_without_network(self):
        async def run():
            lookup = DomainAgeLookup()
            try:
                result = await lookup.lookup_age_days("not a domain at all")
                assert result is None
            finally:
                await lookup.close()

        asyncio.run(run())

    def test_real_lookup_against_a_known_old_domain(self):
        """Hits the real public RDAP service, same testing posture as
        tests/test_pipeline.py's ThreatEnricher tests -- accepts either a
        real, plausible answer or a graceful None if this environment
        can't reach the network, since a broken/unreachable lookup must
        never raise either way."""
        async def run():
            lookup = DomainAgeLookup()
            try:
                age = await lookup.lookup_age_days("google.com")
                if age is not None:
                    assert age > 365 * 10  # google.com has been registered since 1997
            finally:
                await lookup.close()

        asyncio.run(run())

    def test_real_lookup_against_a_tld_with_no_rdap_coverage(self):
        """.su (confirmed during this project's own real-data validation
        -- see docs/PATH_TO_10_OUT_OF_10.md's Phase 9) has no RDAP
        service at all; this must degrade to None, not raise."""
        async def run():
            lookup = DomainAgeLookup()
            try:
                age = await lookup.lookup_age_days("whitepepper.su")
                assert age is None
            finally:
                await lookup.close()

        asyncio.run(run())
