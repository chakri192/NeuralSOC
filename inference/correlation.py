import uuid
import time
from datetime import datetime, timezone
from inference.risk import calculate_risk_score

class IncidentCorrelator:
    def __init__(self, time_window_sec=300, max_tracked_ips=5000):
        self.active_alerts = {}
        self.time_window_sec = time_window_sec
        self.max_tracked_ips = max_tracked_ips
        self.last_cleanup = time.time()

    def add_alert(self, alert: dict) -> dict:
        src_ip = alert.get("source_ip")
        if not src_ip or src_ip == "unknown":
            return None
            
        if src_ip not in self.active_alerts:
            self.active_alerts[src_ip] = []
            
        # PERFORMANCE FIX: Store raw float timestamp to avoid ISO parsing in cleanup loop
        self.active_alerts[src_ip].append({
            "alert": alert, 
            "ts": time.time(),
            "correlated": False
        })
        
        if time.time() - self.last_cleanup > 60:
            self._cleanup_stale_alerts()
            
        return self._evaluate_incident(src_ip)

    def _cleanup_stale_alerts(self):
        now = time.time()
        stale_ips = []
        
        for ip, records in self.active_alerts.items():
            # CPU FIX: Lightning-fast float subtraction (No dateutil.parser)
            valid_records = [r for r in records if (now - r["ts"]) <= self.time_window_sec]
            
            if not valid_records:
                stale_ips.append(ip)
            else:
                self.active_alerts[ip] = valid_records

        for ip in stale_ips:
            del self.active_alerts[ip]

        if len(self.active_alerts) > self.max_tracked_ips:
            sorted_ips = sorted(self.active_alerts.keys(), key=lambda k: len(self.active_alerts[k]))
            excess = len(self.active_alerts) - self.max_tracked_ips
            for ip in sorted_ips[:excess]:
                del self.active_alerts[ip]
                
        self.last_cleanup = now

    def _evaluate_incident(self, src_ip: str) -> dict:
        records = self.active_alerts[src_ip]
        
        # BLINDSPOT FIX: Only evaluate un-correlated alerts to prevent duplicate firing
        uncorrelated_records = [r for r in records if not r["correlated"]]
        
        if len(uncorrelated_records) < 2:
            return None
            
        alerts = [r["alert"] for r in uncorrelated_records]
        tactics = set(a.get("mitre_tactic") for a in alerts if a.get("mitre_tactic"))
        risk_score = calculate_risk_score(alerts)
        
        if len(tactics) >= 2 or risk_score >= 80.0:
            severity = "critical" if risk_score >= 90.0 else ("high" if risk_score >= 75.0 else "medium")
            
            incident = {
                "incident_id": f"INC-{uuid.uuid4().hex[:12]}",
                "created_timestamp": datetime.now(timezone.utc).isoformat(),
                "updated_timestamp": datetime.now(timezone.utc).isoformat(),
                "affected_entities": [src_ip],
                "related_alert_ids": [a.get("alert_id") for a in alerts],
                "threat_classes": list(set(a.get("threat_class") for a in alerts)),
                "risk_score": risk_score,
                "severity": severity,
                "evidence_summary": f"Automated Correlation: Detected {len(alerts)} related alerts traversing {len(tactics)} distinct MITRE tactics from source {src_ip}.",
                "mitre_tactics": list(tactics),
                "mitre_techniques": list(set(a.get("mitre_technique") for a in alerts if a.get("mitre_technique"))),
                "status": "new",
                "analyst_owner": "unassigned",
                "notes": []
            }
            
            # BLINDSPOT FIX: Mark as correlated instead of deleting, preserving memory
            for r in uncorrelated_records:
                r["correlated"] = True
                
            return incident
            
        return None
