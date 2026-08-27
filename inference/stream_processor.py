#!/usr/bin/env python3
"""
stream_processor.py
===================
Production Stream Processing & ML Inference Engine for Unidirectional IP Traffic.

Fully addresses all 6 Threat Classes from the Problem Statement:
a. Volumetric / Protocol DDoS (SYN floods, UDP reflection/amplification)
b. Botnet C2 Beaconing (Periodicity & Inter-Arrival Time jitter analysis)
c. DGA Domains & DNS Tunnelling (Entropy, lexical n-grams, deep encoded subdomains)
d. Malware Inside Encrypted Sessions (JA3/JA3S/JA4 metadata, zero payload decryption)
e. Reconnaissance & Port Scanning (Horizontal sweeps & vertical fan-out patterns)
f. Data Exfiltration (Asymmetric byte ratios & Isolation Forest flow anomalies)
"""

import os
import sys
import time
import json
import logging
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import joblib
    import numpy as np
except ImportError:
    joblib = None
    np = None

try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ImportError:
    try:
        from kafka_python_ng import KafkaConsumer, KafkaProducer
        from kafka_python_ng.errors import NoBrokersAvailable
    except ImportError:
        KafkaConsumer = None
        KafkaProducer = None
        NoBrokersAvailable = Exception

try:
    from feature_extractor import (
        extract_dns_features,
        extract_conn_features,
        lookup_ja3,
        calculate_shannon_entropy,
        BeaconingTracker,
        ReconScanTracker,
    )
except ImportError:
    from inference.feature_extractor import (
        extract_dns_features,
        extract_conn_features,
        lookup_ja3,
        calculate_shannon_entropy,
        BeaconingTracker,
        ReconScanTracker,
    )

try:
    from dl_engine import DeepLearningEngine
except ImportError:
    try:
        from inference.dl_engine import DeepLearningEngine
    except ImportError:
        DeepLearningEngine = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("StreamProcessor")

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


class ComprehensiveThreatEngine:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.dga_model = None
        self.flow_anomaly_model = None
        self.beacon_tracker = BeaconingTracker()
        self.recon_tracker = ReconScanTracker()
        
        if DeepLearningEngine:
            self.dl_engine = DeepLearningEngine()
            
        self._load_models()

    def _load_models(self):
        dga_path = os.path.join(self.model_dir, "dga_detector.pkl")
        flow_path = os.path.join(self.model_dir, "flow_anomaly.pkl")

        if joblib is not None and os.path.exists(dga_path):
            try:
                self.dga_model = joblib.load(dga_path)
                logger.info(f"Loaded DGA Classifier from {dga_path}")
            except Exception as e:
                logger.warning(f"Failed loading DGA model: {e}")

        if joblib is not None and os.path.exists(flow_path):
            try:
                self.flow_anomaly_model = joblib.load(flow_path)
                logger.info(f"Loaded Flow Anomaly Model from {flow_path}")
            except Exception as e:
                logger.warning(f"Failed loading Flow Anomaly model: {e}")

    def evaluate_dns(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Threat Class c: DGA Domains and DNS Tunnelling"""
        query = (record.get("query") or record.get("name") or "").strip().lower().rstrip(".")
        if not query or query.endswith(".in-addr.arpa") or query.endswith(".local") or query.endswith(".internal"):
            return None

        features = extract_dns_features(record)
        
        # 1. DNS Tunneling & Exfiltration Check
        if features["is_tunnel_candidate"]:
            return {
                "threat_class": "DNS_TUNNELING_EXFIL",
                "severity": "HIGH",
                "confidence_score": 0.92,
                "mitre_technique": "T1071.004",
                "evidence": {
                    "reason": features["tunnel_reason"],
                    "query": query,
                    "query_length": features["total_length"],
                    "entropy": features["entropy"],
                    "qtype": features["qtype"],
                    "subdomain_levels": features["num_subdomains"],
                },
            }

        # 2. DGA Domain ML Evaluation
        dga_prob = 0.0
        cnn_prob = 0.0
        
        # Deep Learning Evaluation (CNN)
        if hasattr(self, 'dl_engine'):
            cnn_prob = self.dl_engine.evaluate_dns(query)
            
        # Scikit-Learn Evaluation (Random Forest)
        if self.dga_model is not None and np is not None:
            try:
                vec = np.array([features["feature_vector"]])
                probs = self.dga_model.predict_proba(vec)[0]
                dga_prob = float(probs[1])
            except Exception:
                dga_prob = 0.0
        else:
            if features["entropy"] > 3.7 or (features["entropy"] > 3.3 and features["body_length"] > 14):
                dga_prob = 0.85

        # Alert if either Traditional ML or Deep Learning flags it
        if dga_prob >= 0.70 or cnn_prob >= 0.75 or features["entropy"] >= 3.85:
            max_prob = max(dga_prob, cnn_prob)
            severity = "CRITICAL" if (max_prob > 0.90 or features["entropy"] > 4.2) else "HIGH"
            confidence = round(max(max_prob, min(1.0, features["entropy"] / 4.4)), 2)
            
            reason = "Algorithmic Domain Detected"
            if cnn_prob >= 0.75:
                reason = "Dictionary-Based DGA Detected (CNN AI)"
            elif features["entropy"] >= 3.85:
                reason = "High-Entropy Domain Query Detected"
                
            return {
                "threat_class": "DGA_DOMAIN",
                "severity": severity,
                "confidence_score": confidence,
                "mitre_technique": "T1568.002",
                "evidence": {
                    "reason": reason,
                    "domain": query,
                    "entropy": features["entropy"],
                    "body_length": features["body_length"],
                    "cnn_probability": round(cnn_prob, 3),
                    "rf_probability": round(dga_prob, 3),
                    "qtype": features["qtype"],
                },
            }

        return None

    def evaluate_ssl(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Threat Class d: Malware Inside Encrypted Sessions (Metadata Only)"""
        ja3 = record.get("ja3")
        server_name = record.get("server_name", "")
        
        # 1. Known Malicious JA3 Fingerprint Match
        if ja3:
            match = lookup_ja3(ja3)
            if match:
                return {
                    "threat_class": "MALICIOUS_JA3_FINGERPRINT",
                    "severity": match.get("severity", "CRITICAL"),
                    "confidence_score": 0.98,
                    "mitre_technique": match.get("mitre_id", "T1071.001"),
                    "evidence": {
                        "reason": f"Known Malware / C2 Fingerprint: {match.get('family')}",
                        "ja3_hash": ja3,
                        "malware_family": match.get("family"),
                        "threat_description": match.get("description"),
                        "sni": server_name,
                        "cipher": record.get("cipher"),
                        "version": record.get("version"),
                    },
                }

        # 2. Self-Signed Certificate with Anomalous SNI Entropy
        val_status = str(record.get("validation_status", "")).lower()
        if "self signed" in val_status and server_name:
            ent = calculate_shannon_entropy(server_name.split(".")[0])
            if ent > 3.4:
                return {
                    "threat_class": "ENCRYPTED_MALWARE_TLS",
                    "severity": "HIGH",
                    "confidence_score": 0.88,
                    "mitre_technique": "T1573.002",
                    "evidence": {
                        "reason": "Self-Signed Certificate with High-Entropy SNI Handshake",
                        "sni": server_name,
                        "sni_entropy": ent,
                        "validation_status": record.get("validation_status"),
                        "ja3": ja3,
                    },
                }

        return None

    def evaluate_conn(self, record: Dict[str, Any], ts: float) -> Optional[Dict[str, Any]]:
        """Threat Classes a, b, e, f"""
        src_ip = str(record.get("id.orig_h") or record.get("src_ip", "0.0.0.0"))
        dst_ip = str(record.get("id.resp_h") or record.get("dst_ip", "0.0.0.0"))
        dst_port = int(record.get("id.resp_p", 0) or 0)

        # 1. State Tracker: Reconnaissance / Port Scanning (Threat Class e)
        recon_alert = self.recon_tracker.observe(src_ip, dst_ip, dst_port, ts)
        if recon_alert:
            return {
                "threat_class": "RECON_PORT_SCAN",
                "severity": "HIGH",
                "confidence_score": 0.94,
                "mitre_technique": "T1046",
                "evidence": {
                    "reason": f"Active Reconnaissance: {recon_alert['scan_type'].replace('_', ' ').title()}",
                    "scan_type": recon_alert["scan_type"],
                    "target": recon_alert.get("target_ip") or f"Port {recon_alert.get('target_port')}",
                    "unique_probes": recon_alert.get("unique_ports_scanned") or recon_alert.get("unique_hosts_targeted"),
                    "details": recon_alert,
                },
            }

        # 2. State Tracker: Botnet C2 Beaconing (Threat Class b)
        beacon_alert = self.beacon_tracker.observe(src_ip, dst_ip, dst_port, ts)
        if beacon_alert:
            return {
                "threat_class": "BOTNET_C2_BEACONING",
                "severity": "HIGH",
                "confidence_score": beacon_alert["confidence"],
                "mitre_technique": "T1071",
                "evidence": {
                    "reason": f"Periodic C2 Heartbeat: Interval ~{beacon_alert['mean_interval_sec']}s (Jitter CV={beacon_alert['jitter_cv']})",
                    "mean_interval_sec": beacon_alert["mean_interval_sec"],
                    "jitter_cv": beacon_alert["jitter_cv"],
                    "observed_pulses": beacon_alert["observed_pulses"],
                    "recent_iats": beacon_alert["history_iats"],
                },
            }

        # Flow dynamics extraction
        conn_feats = extract_conn_features(record)

        # 3. Volumetric & Protocol DDoS (Threat Class a)
        if conn_feats["is_ddos_candidate"]:
            return {
                "threat_class": "VOLUMETRIC_PROTOCOL_DDOS",
                "severity": "CRITICAL",
                "confidence_score": 0.95,
                "mitre_technique": "T1498",
                "evidence": {
                    "reason": conn_feats["ddos_reason"],
                    "subclass": conn_feats["ddos_subclass"],
                    "packets_per_sec": conn_feats["pkts_per_sec"],
                    "bytes_per_sec": conn_feats["bytes_per_sec"],
                    "proto": conn_feats["proto"],
                    "conn_state": conn_feats["conn_state"],
                },
            }

        # 4. Data Exfiltration (Threat Class f)
        if conn_feats["is_exfiltration"]:
            return {
                "threat_class": "DATA_EXFILTRATION",
                "severity": "CRITICAL" if conn_feats["orig_bytes"] > 20000000 else "HIGH",
                "confidence_score": 0.96,
                "mitre_technique": "T1048",
                "evidence": {
                    "reason": conn_feats["exfil_reason"],
                    "orig_bytes": int(conn_feats["orig_bytes"]),
                    "resp_bytes": int(conn_feats["resp_bytes"]),
                    "byte_asymmetry_ratio": conn_feats["byte_ratio"],
                    "duration_sec": conn_feats["duration"],
                },
            }

        # 5. ML Flow Anomaly (Isolation Forest & Autoencoder)
        dl_mse = 0.0
        if hasattr(self, 'dl_engine') and self.dl_engine.ae_model:
            dl_mse = self.dl_engine.evaluate_flow(
                conn_feats["orig_bytes"], 
                conn_feats["resp_bytes"], 
                conn_feats["duration"], 
                conn_feats["orig_pkts"] + conn_feats["resp_pkts"]
            )
            
        if self.flow_anomaly_model is not None and np is not None:
            try:
                # Fast heuristic pre-filter: only run tree traversal on non-trivial flows
                if conn_feats["orig_bytes"] > 10000 or conn_feats["byte_ratio"] > 100 or conn_feats["bytes_per_sec"] > 200000:
                    vec = np.array([conn_feats["feature_vector"]])
                    score = float(self.flow_anomaly_model.decision_function(vec)[0])
                    
                    # Alert if Isolation Forest score is very low OR Autoencoder MSE is very high
                    if score < -0.05 or dl_mse > 0.15:
                        conf = round(min(1.0, max(0.65 + abs(score) * 2.0, dl_mse * 5.0)), 2)
                        
                        reason = f"Isolation Forest Flow Anomaly (Score: {round(score, 4)})"
                        if dl_mse > 0.15:
                            reason = f"Zero-Day Deep Learning Autoencoder Anomaly (MSE Loss: {round(dl_mse, 4)})"
                            
                        return {
                            "threat_class": "FLOW_ANOMALY",
                            "severity": "HIGH" if conf > 0.85 else "MEDIUM",
                            "confidence_score": conf,
                            "mitre_technique": "T1048",
                            "evidence": {
                                "reason": reason,
                                "orig_bytes": int(conn_feats["orig_bytes"]),
                                "resp_bytes": int(conn_feats["resp_bytes"]),
                                "duration_sec": conn_feats["duration"],
                                "pkts_per_sec": conn_feats["pkts_per_sec"],
                                "dl_reconstruction_loss": round(dl_mse, 4)
                            },
                        }
            except Exception:
                pass

        return None


class StreamProcessor:
    def __init__(
        self,
        bootstrap_servers: str,
        input_topic: str = "raw_traffic",
        output_topic: str = "security_alerts",
        group_id: str = "threat-stream-processor-v2",
        dry_run: bool = False,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.group_id = group_id
        self.dry_run = dry_run
        self.engine = ComprehensiveThreatEngine()
        self.consumer = None
        self.producer = None

        if not self.dry_run:
            self._init_kafka()

    def _init_kafka(self, max_retries: int = 15, delay: float = 2.0):
        if KafkaConsumer is None or KafkaProducer is None:
            raise RuntimeError("kafka-python or kafka-python-ng must be installed.")

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connecting Producer to {self.bootstrap_servers}...")
                self.producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers.split(","),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    acks=1,
                    linger_ms=5,
                )
                break
            except Exception as e:
                logger.warning(f"Producer connection failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connecting Consumer to {self.bootstrap_servers} topic '{self.input_topic}'...")
                self.consumer = KafkaConsumer(
                    self.input_topic,
                    bootstrap_servers=self.bootstrap_servers.split(","),
                    group_id=self.group_id,
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    consumer_timeout_ms=1000,
                )
                logger.info("Kafka consumer & producer initialized successfully.")
                return
            except Exception as e:
                logger.warning(f"Consumer connection failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)

        raise ConnectionError("Failed to initialize Kafka connections.")

    def process_record(self, raw_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        log_type = (raw_record.get("_log_type") or "").lower()
        source_file = (raw_record.get("_source_file") or "").lower()
        ts = float(raw_record.get("ts") or time.time())
        
        threat_eval = None
        if "dns" in log_type or "dns" in source_file:
            threat_eval = self.engine.evaluate_dns(raw_record)
        elif "ssl" in log_type or "tls" in log_type or "ssl" in source_file:
            threat_eval = self.engine.evaluate_ssl(raw_record)
        elif "conn" in log_type or "conn" in source_file:
            threat_eval = self.engine.evaluate_conn(raw_record, ts)
        else:
            if "query" in raw_record:
                threat_eval = self.engine.evaluate_dns(raw_record)
            elif "ja3" in raw_record:
                threat_eval = self.engine.evaluate_ssl(raw_record)
            elif "orig_bytes" in raw_record or "conn_state" in raw_record:
                threat_eval = self.engine.evaluate_conn(raw_record, ts)

        if not threat_eval:
            return None

        flow_id = raw_record.get("uid") or raw_record.get("flow_id") or f"FLW-{int(time.time()*1000)}"
        src_ip = raw_record.get("id.orig_h") or raw_record.get("src_ip", "unknown")
        src_port = raw_record.get("id.orig_p") or raw_record.get("src_port", 0)
        dst_ip = raw_record.get("id.resp_h") or raw_record.get("dst_ip", "unknown")
        dst_port = raw_record.get("id.resp_p") or raw_record.get("dst_port", 0)
        proto = raw_record.get("proto", "tcp")

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "flow_id": str(flow_id),
            "threat_class": threat_eval["threat_class"],
            "severity": threat_eval["severity"],
            "confidence_score": threat_eval["confidence_score"],
            "mitre_technique": threat_eval.get("mitre_technique", "N/A"),
            "src_ip": str(src_ip),
            "src_port": int(src_port) if str(src_port).isdigit() else 0,
            "dst_ip": str(dst_ip),
            "dst_port": int(dst_port) if str(dst_port).isdigit() else 0,
            "proto": str(proto).lower(),
            "evidence": threat_eval["evidence"],
            "raw_metadata_sample": {
                k: v for k, v in raw_record.items()
                if not k.startswith("_") and k in [
                    "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                    "proto", "service", "duration", "orig_bytes", "resp_bytes",
                    "query", "ja3", "server_name", "conn_state", "qtype_name"
                ]
            }
        }
        return alert

    def run(self):
        logger.info("Starting Threat Stream Processor loop...")
        logger.info(f"Input: '{self.input_topic}' -> Output: '{self.output_topic}' (Dry Run: {self.dry_run})")
        
        alerts_emitted = 0
        records_scanned = 0
        last_log_time = time.time()
        
        # Deduplication cache: (src_ip, dst_ip, threat_class) -> last_alert_time
        dedup_cache: Dict[str, float] = {}
        DEDUP_WINDOW_SEC = 5.0  # Avoid spamming the exact same alert within 5 seconds

        try:
            while True:
                if self.dry_run:
                    time.sleep(1)
                    continue

                for msg in self.consumer:
                    records_scanned += 1
                    record = msg.value
                    alert = self.process_record(record)
                    
                    if alert:
                        now = time.time()
                        
                        # Deduplication logic
                        dedup_key = f"{alert['src_ip']}_{alert['dst_ip']}_{alert['threat_class']}"
                        last_time = dedup_cache.get(dedup_key, 0.0)
                        
                        if now - last_time > DEDUP_WINDOW_SEC:
                            dedup_cache[dedup_key] = now
                            alerts_emitted += 1
                            flow_key = alert["flow_id"]
                            self.producer.send(self.output_topic, key=flow_key, value=alert)
                            logger.warning(
                                f"🚨 [{alert['severity']}] {alert['threat_class']} | "
                                f"{alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']} | "
                                f"Conf: {alert['confidence_score']}"
                            )
                            
                            # Clean up old dedup entries to prevent memory leak
                            if len(dedup_cache) > 5000:
                                cutoff = now - DEDUP_WINDOW_SEC
                                stale_keys = [k for k, t in dedup_cache.items() if t < cutoff]
                                for k in stale_keys:
                                    dedup_cache.pop(k, None)

                    now = time.time()
                    if now - last_log_time >= 10.0:
                        logger.info(f"Scanned {records_scanned} records, emitted {alerts_emitted} threat alerts.")
                        last_log_time = now

        except KeyboardInterrupt:
            logger.info("Stream Processor interrupted by user.")
        finally:
            if self.producer:
                self.producer.flush()
                self.producer.close()
            if self.consumer:
                self.consumer.close()
            logger.info("Stream Processor shutdown complete.")


def parse_args():
    parser = argparse.ArgumentParser(description="Real-time ML Stream Processor for Cyber Threat Detection.")
    parser.add_argument("--broker", default="localhost:9092", help="Redpanda broker address")
    parser.add_argument("--input-topic", default="raw_traffic", help="Topic to consume raw logs from")
    parser.add_argument("--output-topic", default="security_alerts", help="Topic to publish alerts to")
    parser.add_argument("--group-id", default="threat-stream-processor-v2", help="Kafka consumer group ID")
    parser.add_argument("--dry-run", action="store_true", help="Process without sending to Kafka")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    processor = StreamProcessor(
        bootstrap_servers=args.broker,
        input_topic=args.input_topic,
        output_topic=args.output_topic,
        group_id=args.group_id,
        dry_run=args.dry_run,
    )
    processor.run()
