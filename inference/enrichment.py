import asyncio
import json
import logging
import urllib.request
from urllib.error import URLError

logger = logging.getLogger(__name__)

class ThreatEnricher:
    def __init__(self):
        pass

    async def _fetch_intel(self, ip: str) -> dict:
        loop = asyncio.get_running_loop()
        # Prevent SSRF: Only query strictly formatted public IPv4 addresses
        import re
        if not re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip):
            return {}
        if ip.startswith("169.254.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127."):
            return {}
            
        try:
            # Query a public IP API for live geolocation and AS data
            req = urllib.request.Request(
                f"https://ipapi.co/{ip}/json/",
                headers={'User-Agent': 'NeuralSOC-Enrichment/1.0'}
            )
            # Run blocking URL fetch in executor to avoid hanging event loop
            response = await loop.run_in_executor(
                None, 
                urllib.request.urlopen, 
                req, timeout=5.0
            )
            return json.loads(response.read().decode())
        except Exception as e:
            logger.error(f"Live Intel API failure for {ip}: {e}")
            return {}

    async def enrich(self, alert: dict) -> dict:
        src_ip = alert.get("source_ip", "")
        if not src_ip or src_ip in ["127.0.0.1", "localhost"] or src_ip.startswith("10.") or src_ip.startswith("192.168."):
            target_ip = alert.get("destination_ip", "")
            ip_to_check = target_ip if target_ip else src_ip
        else:
            ip_to_check = src_ip

        intel_data = await self._fetch_intel(ip_to_check)

        evidence = alert.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}

        if intel_data and intel_data.get("status") == "success":
            evidence["Live GeoIP"] = f"{intel_data.get('city', 'Unknown')}, {intel_data.get('countryCode', 'Unknown')}"
            evidence["Live ISP"] = intel_data.get('isp', 'Unknown')
            if intel_data.get("hosting"):
                evidence["Threat Intel"] = "WARNING: Data Center / Bulletproof Hosting Detected"

        alert["evidence"] = evidence
        return alert
