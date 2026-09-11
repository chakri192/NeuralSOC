"""Domain registration-age lookup via free, public RDAP (RFC 7482+) --
a genuinely different, complementary signal to the DGA CNN's per-domain
character classification: real malicious domains are typically
registered days to months before use, while real legitimate
infrastructure is typically years to decades old. Verified against the
real Lumma Stealer capture's actual malicious domains before being
trusted -- see docs/PATH_TO_10_OUT_OF_10.md's Phase 9 and SECURITY.md
for the full real-data validation (9 to 261 days for confirmed-malicious
domains vs. decades for google.com/microsoft.com/wikipedia.org/github.com).

Only looked up for domains the CNN has ALREADY flagged as suspicious,
never for every DNS query -- both to bound how many real external
network calls this makes, and because sending every domain a monitored
network queries to a third party is a real privacy trade-off this
project isn't making unilaterally for every query, only for ones
already flagged (see inference/stream_processor_faust.py's call site).

Real, disclosed limitations, same session that validated the signal:
RDAP coverage varies by TLD -- confirmed no RDAP service exists for
.su, a TLD real malware in this project's own investigation used, and
whitepepper.su (arguably the strongest real signal in that whole
capture) would get no signal from this lookup at all. A young-but-
legitimate domain (a real new startup, e.g.) will also trigger this,
which is exactly why it becomes its own detection fed into
inference/risk.py's log-odds pooling alongside the CNN's own verdict,
not a standalone confirm/deny.
"""
import collections
import logging
import re
import ssl
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import dateutil.parser
import httpx

logger = logging.getLogger(__name__)

_RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
_REQUEST_TIMEOUT_SEC = 3.0
_MAX_RESPONSE_BYTES = 65536

# ~6 months -- the real Lumma-capture malicious domains this was
# calibrated against ranged 9-261 days; real legitimate infrastructure
# checked alongside them was decades old, so this threshold sits well
# clear of the real malicious range while leaving real margin against
# a merely-young-but-legitimate domain.
YOUNG_DOMAIN_DAYS_THRESHOLD = 180.0

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def extract_registrable_domain(query: str) -> Optional[str]:
    """Last two DNS labels -- the same simple SLD heuristic
    inference/models.py's own multi-segment defense already uses (not
    fully correct for multi-part TLDs like .co.uk, a known, pre-existing
    limitation shared with that code, not a new one here). Returns None
    for anything that doesn't look like a syntactically real domain --
    used both to skip a wasted lookup and as a defense-in-depth check
    before this string is ever embedded in a request URL.
    """
    if not query:
        return None
    clean = query.strip().rstrip(".").lower()
    parts = [p for p in clean.split(".") if p]
    if len(parts) < 2:
        return None
    sld = ".".join(parts[-2:])
    if len(sld) > 253:
        return None
    if not all(_DOMAIN_LABEL_RE.match(label) for label in parts[-2:]):
        return None
    return sld


def confidence_for_age(age_days: float) -> float:
    """Younger -> higher confidence, linearly, clamped to [0.55, 0.95].
    A domain right at the threshold still contributes real (if modest)
    corroborating evidence via log-odds pooling rather than a sharp 0/1
    cliff; nothing here is asserted with the same near-certainty the DGA
    CNN can report for an unambiguous case, since a young-but-legitimate
    domain is a real, known false-positive mode for this signal alone.
    """
    fraction_young = max(0.0, min(1.0, 1.0 - (age_days / YOUNG_DOMAIN_DAYS_THRESHOLD)))
    return 0.55 + 0.40 * fraction_young


class DomainAgeLookup:
    def __init__(self, cache_ttl_sec: int = 86400, max_cache_size: int = 5000):
        # Same hardened TLS posture as inference/enrichment.py's
        # ThreatEnricher -- one implementation of "how this project talks
        # TLS to a third party" to audit is the goal, though this is a
        # second client instance (different pinned host, different data
        # shape) rather than a shared one.
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.client = httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SEC, verify=ssl_context)
        self._cache: "collections.OrderedDict[str, tuple]" = collections.OrderedDict()
        self._cache_ttl = cache_ttl_sec
        self._max_cache_size = max_cache_size

    async def close(self):
        await self.client.aclose()

    def _get_cached(self, domain: str):
        if domain in self._cache:
            value, exp = self._cache[domain]
            if time.time() < exp:
                self._cache.move_to_end(domain)
                return value
            self._cache.pop(domain, None)
        return "MISS"

    def _set_cached(self, domain: str, value):
        if domain in self._cache:
            self._cache.move_to_end(domain)
        self._cache[domain] = (value, time.time() + self._cache_ttl)
        while len(self._cache) > self._max_cache_size:
            self._cache.popitem(last=False)

    async def lookup_age_days(self, query: str) -> Optional[float]:
        """Returns the domain's age in days at lookup time, or None if
        unavailable (no RDAP coverage for this TLD, malformed domain,
        network error, malformed response, etc.) -- fails closed to "no
        signal" on every path, never raises, matching
        DeepLearningEngine.predict()'s and FlowAnomalyEngine.score()'s
        own posture: a broken or rate-limited lookup degrades to
        "nothing learned here", not a pipeline failure.
        """
        domain = extract_registrable_domain(query)
        if not domain:
            return None

        cached = self._get_cached(domain)
        if cached != "MISS":
            return cached

        age_days = await self._fetch_age_days(domain)
        self._set_cached(domain, age_days)
        return age_days

    async def _fetch_age_days(self, domain: str) -> Optional[float]:
        try:
            resp = await self.client.get(
                _RDAP_BOOTSTRAP_URL.format(domain=quote(domain, safe="")),
                headers={"User-Agent": "NeuralSOC-DomainAge/1.0", "Accept": "application/rdap+json"},
                # rdap.org's bootstrap redirects to the authoritative
                # registry's own RDAP server (Verisign for .com, etc.) --
                # unlike ThreatEnricher's IP lookup (one pinned host,
                # redirects rejected outright), following exactly this
                # kind of redirect is RDAP's own intended, standardized
                # discovery mechanism, and the target is determined by
                # IANA's own bootstrap registry data, not by anything an
                # attacker-controlled domain string could steer.
                follow_redirects=True,
            )
            if resp.status_code != 200:
                return None
            if len(resp.content) > _MAX_RESPONSE_BYTES:
                logger.warning("RDAP response exceeded size limit for %s", domain)
                return None
            data = resp.json()
            if not isinstance(data, dict):
                return None
            for event in data.get("events") or []:
                if not isinstance(event, dict):
                    continue
                if event.get("eventAction") == "registration":
                    return self._parse_age_days(event.get("eventDate"))
            return None
        except Exception as e:
            logger.debug("RDAP lookup failed for %s: %s", domain, e)
            return None

    @staticmethod
    def _parse_age_days(event_date: Optional[str]) -> Optional[float]:
        if not event_date or not isinstance(event_date, str):
            return None
        try:
            # dateutil.parser.isoparse (already a project dependency, used
            # the same way in shared/formatters.py) rather than
            # datetime.fromisoformat: real RDAP responses (confirmed live,
            # e.g. centralnic's "2025-12-09T08:20:51.0Z") use a single-digit
            # fractional second, which fromisoformat only accepts on
            # Python 3.11+ -- this project runs on 3.10, where it raised
            # ValueError on every real response and silently produced "no
            # signal" for every domain, found by comparing a live 200 OK
            # RDAP response against this function returning None for the
            # same domain.
            reg_date = dateutil.parser.isoparse(event_date)
            if reg_date.tzinfo is None:
                reg_date = reg_date.replace(tzinfo=timezone.utc)
            age_seconds = (datetime.now(timezone.utc) - reg_date).total_seconds()
            return max(0.0, age_seconds / 86400.0)
        except (ValueError, TypeError, OverflowError):
            return None
