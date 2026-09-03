"""
Centralized Data Access Layer.
Fetches data from the enterprise FastAPI Backend instead of Kafka directly.
This allows historical persistence and decouples the UI from the message broker.
"""
import os
import requests
import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("data_access")

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1")
# SECURITY FIX: Dynamically pull API key from environment, fallback for local demo only
API_KEY = os.environ.get("TSOC_API_KEY", "")
if not API_KEY:
    raise RuntimeError("TSOC_API_KEY not set") 

class DataStreamManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DataStreamManager, cls).__new__(cls)
                cls._instance._init_state()
            return cls._instance

    def _init_state(self):
        self.alerts = []
        self.stats = {"total_alerts": 0, "critical": 0, "high": 0, "medium": 0}
        
        self.is_running = False
        self.broker_healthy = False
        self.last_event_time = 0.0
        
        # PERFORMANCE FIX: Persistent HTTP Session avoids TCP handshake overhead
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": API_KEY})

    def start_listeners(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            
        threading.Thread(target=self._poll_api, daemon=True).start()

    def _poll_api(self):
        while self.is_running:
            try:
                # Fetch Alerts via persistent session
                resp_alerts = self.session.get(f"{API_URL}/alerts?limit=200", timeout=3)
                if resp_alerts.status_code == 200:
                    self.alerts = resp_alerts.json()
                    self.broker_healthy = True
                    self.last_event_time = time.time()
                
                # Fetch Stats via persistent session
                resp_stats = self.session.get(f"{API_URL}/stats", timeout=3)
                if resp_stats.status_code == 200:
                    self.stats = resp_stats.json()
                    
            except Exception as e:
                self.broker_healthy = False
                logger.error(f"[DataAccess] Failed to connect to API: {e}")
                
            time.sleep(2) # Poll every 2 seconds
                
    def get_incidents(self) -> list:
        return self.alerts
        
    def get_alerts(self) -> list:
        formatted = []
        for a in self.alerts:
            import json
            if isinstance(a.get("evidence"), str):
                try:
                    a["evidence"] = json.loads(a["evidence"])
                except:
                    pass
            formatted.append(a)
        return formatted
        
    def status(self) -> dict:
        return {
            "broker_healthy": self.broker_healthy,
            "last_event_time": self.last_event_time,
            "incident_count": len(self.alerts),
            "alert_count": len(self.alerts),
            "stats": self.stats
        }

# Global singleton accessor
stream_manager = DataStreamManager()
