import collections
import asyncio
import ipaddress
import json
import logging
import ssl
import time
from typing import Tuple
import httpx

from inference.playbooks import enrich_ip_intel

logger = logging.getLogger(__name__)

class ThreatEnricher:
    def __init__(self, cache_ttl_sec: int = 86400, max_cache_size: int = 5000):
        # Enforce hardened TLS 1.2+ context with strict certificate verification
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.client = httpx.AsyncClient(timeout=2.0, verify=ssl_context)
        self._cache: collections.OrderedDict[str, Tuple[dict, float]] = collections.OrderedDict()
        self._cache_ttl = cache_ttl_sec
        self._max_cache_size = max_cache_size

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        await self.client.aclose()

    def _get_cached(self, ip: str) -> dict:
        if ip in self._cache:
            data, exp = self._cache[ip]
            if time.time() < exp:
                self._cache.move_to_end(ip)
                return data
            else:
                self._cache.pop(ip, None)
        return {}

    def _set_cached(self, ip: str, data: dict):
        if ip in self._cache:
            self._cache.move_to_end(ip)
        self._cache[ip] = (data, time.time() + self._cache_ttl)
        while len(self._cache) > self._max_cache_size:
            self._cache.popitem(last=False)

    async def _fetch_intel(self, ip: str) -> dict:
        # Check cache first for 0ms lookup and zero egress overhead
        cached = self._get_cached(ip)
        if cached:
            return cached

        # Strict Zero-Trust SSRF Defense: parse and validate IPv4 object directly
        try:
            ip_str = ip.strip()
            addr = ipaddress.ip_address(ip_str)
            # Must be valid IPv4 and publicly routable (reject private, non-global, loopback, link-local, multicast, reserved)
            if (
                addr.version != 4
                or not addr.is_global
                or addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
                or addr in ipaddress.ip_network("100.64.0.0/10")
                or addr in ipaddress.ip_network("169.254.0.0/16")
            ):
                return {}
            clean_ip = str(addr)
        except ValueError:
            return {}

        try:
            # Pinned allow-list: only ipwho.is; reject any redirect to other hosts (SSRF defense).
            # ipapi.co's free tier caps out around 1,000 lookups/day (~1/min
            # sustained) -- observed exhausting itself within seconds under
            # real simulated traffic, after which every enrichment silently
            # fell back to the offline heuristic for the rest of the run.
            # ipwho.is is free, needs no API key or signup either, and its
            # documented limits are materially higher for the same
            # no-signup tier. Also allow-listed in
            # k8s/cilium-identity-policy.yaml -- update both together.
            # Limit response read size to 64KB to prevent OOM
            response = await self.client.get(
                f"https://ipwho.is/{clean_ip}",
                headers={'User-Agent': 'NeuralSOC-Enrichment/1.0'},
                follow_redirects=False,  # Reject redirect-based SSRF
            )
            response.raise_for_status()
            if len(response.content) > 65536:
                logger.warning("Enrichment response exceeded 64KB limit for %s; rejecting.", clean_ip)
                return {}
            data = response.json()
            if data and data.get("success") and isinstance(data.get("ip"), str) and data.get("ip") == clean_ip:
                self._set_cached(clean_ip, data)
                return data
        except httpx.HTTPError as e:
            logger.debug(f"Live Intel API HTTP error for {clean_ip}: {e}; falling back to local threat intel")
        except Exception as e:
            logger.debug(f"Live Intel API unreachable for {clean_ip}: {e}; falling back to local threat intel")

        # Resilient Zero-Trust offline fallback: populate high-fidelity deterministic metadata
        fallback_intel = enrich_ip_intel(clean_ip)
        adapted_data = {
            "city": "Unknown",
            "country_name": fallback_intel.get("country", "Unknown"),
            "org": fallback_intel.get("asn", "Unknown"),
            "hosting": "Bulletproof" in fallback_intel.get("reputation", "")
        }
        self._set_cached(clean_ip, adapted_data)
        return adapted_data

    async def enrich(self, alert: dict) -> dict:
        src_ip = alert.get("source_ip", "")
        ip_to_check = src_ip
        try:
            addr = ipaddress.ip_address(src_ip.strip())
            if addr.is_private or addr.is_loopback:
                target_ip = alert.get("destination_ip", "")
                if target_ip:
                    ip_to_check = target_ip
        except ValueError:
            target_ip = alert.get("destination_ip", "")
            if target_ip:
                ip_to_check = target_ip

        intel_data = await self._fetch_intel(ip_to_check)

        evidence = alert.get("evidence", {})
        if not isinstance(evidence, dict):
            try:
                if isinstance(evidence, str):
                    if len(evidence) > 65536:
                        evidence = {"warning": "Evidence string exceeds 64KB maximum limit"}
                    else:
                        evidence = json.loads(evidence)
                else:
                    evidence = {}
            except Exception:
                evidence = {}

        # intel_data is either ipwho.is's raw response (top-level "country",
        # nested "connection": {isp, org}, no "hosting" key) or the offline
        # enrich_ip_intel() fallback's adapted shape ("country_name", "org",
        # a real "hosting" bool) -- checked in that order so either shape
        # populates the same evidence fields.
        if intel_data:
            connection = intel_data.get("connection") or {}
            city = intel_data.get('city') or 'Unknown'
            country = intel_data.get('country') or intel_data.get('country_name') or intel_data.get('country_code') or 'Unknown'
            isp = connection.get('isp') or connection.get('org') or intel_data.get('org') or intel_data.get('isp') or 'Unknown'
            evidence["Live GeoIP"] = f"{city}, {country}"
            evidence["Live ISP"] = isp
            # Only the offline fallback ever sets "hosting" -- ipwho.is's
            # free tier has no bulletproof-hosting signal, same as ipapi.co's
            # free tier before it.
            if intel_data.get("hosting"):
                evidence["Threat Intel"] = "WARNING: Data Center / Bulletproof Hosting Detected"

        alert["evidence"] = evidence
        return alert
