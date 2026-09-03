import asyncio
import hashlib

class ThreatEnricher:
    """
    Simulates a Threat Intelligence and GeoIP integration.
    Uses deterministic hashing so the same IP address will always map to the 
    same Country and Threat Group, ensuring a highly realistic, repeatable demo.
    """
    def __init__(self):
        self.countries = [
            "RU (Russia)", "CN (China)", "KP (North Korea)", 
            "IR (Iran)", "BR (Brazil)", "RO (Romania)", 
            "US (United States)", "NL (Netherlands)", "UA (Ukraine)"
        ]
        
        self.intel_tags = [
            "Tor Exit Node", 
            "Known Botnet Infrastructure", 
            "Bulletproof Hosting", 
            "APT29 Associated (Midnight Blizzard)", 
            "Lazarus Group Infrastructure"
        ]

    def get_deterministic_geo(self, ip_address: str) -> str:
        if not ip_address or ip_address == "unknown":
            return "Unknown"
            
        # Deterministic hash to map IP to a country
        h = int(hashlib.md5(ip_address.encode(), usedforsecurity=False).hexdigest(), 16)
        return self.countries[h % len(self.countries)]

    def get_deterministic_intel(self, ip_address: str, severity: str) -> str:
        # Only enrich high/critical alerts with APT groups
        if severity not in ["high", "critical"]:
            return None
            
        h = int(hashlib.md5((ip_address + "intel").encode(), usedforsecurity=False).hexdigest(), 16)
        
        # Only 40% of critical alerts get a specific APT tag to maintain realism
        if h % 100 < 40:
            return self.intel_tags[h % len(self.intel_tags)]
        return None

    async def enrich(self, alert: dict) -> dict:
        # Simulate an asynchronous external API call
        await asyncio.sleep(0.005)
        src_ip = alert.get("source_ip", "")
        
        # Determine if the attack is Inbound or Outbound
        if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."):
            # Internal source. The threat actor is the destination (e.g. Data Exfil or C2 Beaconing)
            target_ip = alert.get("destination_ip", "")
            geo = self.get_deterministic_geo(target_ip)
            intel = self.get_deterministic_intel(target_ip, alert.get("severity"))
            direction = "Destination"
        else:
            # External source. The threat actor is inbound (e.g. DDoS or Recon)
            geo = self.get_deterministic_geo(src_ip)
            intel = self.get_deterministic_intel(src_ip, alert.get("severity"))
            direction = "Source"

        evidence = alert.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}

        # Inject the new enrichment data directly into the evidence payload
        evidence[f"GeoIP ({direction})"] = geo
        if intel:
            evidence["Threat Intel"] = f"CRITICAL MATCH: {intel}"

        alert["evidence"] = evidence
        return alert
