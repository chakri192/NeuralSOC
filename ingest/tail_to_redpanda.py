#!/usr/bin/env python3
"""
tail_to_redpanda.py
===================
Passively tails live Zeek JSON logs (conn.log, dns.log, ssl.log, etc.)
and streams parsed records to the 'raw_traffic' Redpanda topic.

Implements `tail -F` semantics:
- Tracks file handles across truncation and log rotation (inode changes).
- Zero packet modification / zero reverse path (strictly read-only).
- Low latency, non-blocking batch producer with bounded buffers.
"""

import os
import sys
import time
import json
import glob
import logging
import argparse
from typing import Dict, Optional, Generator

try:
    from kafka import KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ImportError:
    try:
        from kafka_python_ng import KafkaProducer
        from kafka_python_ng.errors import NoBrokersAvailable
    except ImportError:
        KafkaProducer = None
        NoBrokersAvailable = Exception

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ZeekIngest")


class FileTailer:
    """
    Robust log file follower with inode tracking (survives rotations & truncations).
    """
    def __init__(self, filepath: str, from_beginning: bool = False):
        self.filepath = filepath
        self.from_beginning = from_beginning
        self.file_obj = None
        self.current_inode = None
        self._open_file()

    def _open_file(self):
        if self.file_obj:
            try:
                self.file_obj.close()
            except Exception:
                pass
            self.file_obj = None

        if os.path.exists(self.filepath):
            try:
                st = os.stat(self.filepath)
                self.current_inode = st.st_ino
                self.file_obj = open(self.filepath, "r", encoding="utf-8", errors="replace")
                if not self.from_beginning:
                    self.file_obj.seek(0, os.SEEK_END)
                logger.info(f"Opened {self.filepath} (inode={self.current_inode}, size={st.st_size} bytes)")
            except Exception as e:
                logger.warning(f"Unable to open {self.filepath}: {e}")
                self.file_obj = None

    def read_lines(self) -> Generator[str, None, None]:
        # Check if file was rotated or newly created
        if not os.path.exists(self.filepath):
            if self.file_obj:
                logger.warning(f"File {self.filepath} disappeared.")
                self.file_obj.close()
                self.file_obj = None
                self.current_inode = None
            return

        try:
            st = os.stat(self.filepath)
            # Inode changed or file truncated
            if self.file_obj is None or st.st_ino != self.current_inode:
                logger.info(f"File rotation detected on {self.filepath}. Reopening...")
                self._open_file()
            elif self.file_obj and self.file_obj.tell() > st.st_size:
                logger.info(f"File truncation detected on {self.filepath}. Seeking to start...")
                self.file_obj.seek(0, os.SEEK_SET)
        except OSError:
            return

        if not self.file_obj:
            return

        while True:
            line = self.file_obj.readline()
            if not line:
                break
            line_str = line.strip()
            if line_str:
                yield line_str


def get_log_type_from_filename(filename: str) -> str:
    base = os.path.basename(filename).lower()
    if "conn" in base:
        return "conn"
    elif "dns" in base:
        return "dns"
    elif "ssl" in base or "tls" in base:
        return "ssl"
    elif "http" in base:
        return "http"
    elif "quic" in base:
        return "quic"
    return "generic"


class ZeekToRedpandaIngestor:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        log_dir: str,
        poll_interval: float = 0.05,
        from_beginning: bool = False,
        dry_run: bool = False,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.log_dir = log_dir
        self.poll_interval = poll_interval
        self.from_beginning = from_beginning
        self.dry_run = dry_run
        self.tailers: Dict[str, FileTailer] = {}
        self.producer = None

        if not self.dry_run:
            self._connect_producer()

    def _connect_producer(self, max_retries: int = 15, delay: float = 2.0):
        if KafkaProducer is None:
            raise RuntimeError("kafka-python or kafka-python-ng must be installed.")

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connecting to Redpanda at {self.bootstrap_servers} (attempt {attempt}/{max_retries})...")
                self.producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers.split(","),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    acks=1,
                    linger_ms=10,  # low-latency batching
                    compression_type=None,
                    max_block_ms=10000,
                )
                logger.info("Successfully connected to Redpanda broker.")
                return
            except Exception as e:
                logger.warning(f"Broker connection failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)

        raise ConnectionError(f"Could not connect to Redpanda broker at {self.bootstrap_servers}")

    def discover_logs(self):
        patterns = [
            os.path.join(self.log_dir, "*.log"),
            os.path.join(self.log_dir, "conn.log"),
            os.path.join(self.log_dir, "dns.log"),
            os.path.join(self.log_dir, "ssl.log"),
        ]
        found_files = set()
        for pat in patterns:
            for filepath in glob.glob(pat):
                found_files.add(os.path.abspath(filepath))

        for filepath in found_files:
            if filepath not in self.tailers:
                logger.info(f"Discovered new Zeek log: {filepath}")
                self.tailers[filepath] = FileTailer(filepath, from_beginning=self.from_beginning)

    def process_record(self, raw_line: str, log_type: str, filepath: str) -> Optional[dict]:
        # Zeek JSON format check
        if not raw_line.startswith("{"):
            # Could be tab-separated Zeek log header or comment
            return None

        try:
            record = json.loads(raw_line)
            # Normalize and augment with metadata
            record["_log_type"] = log_type
            record["_source_file"] = os.path.basename(filepath)
            record["_ingest_ts"] = time.time()
            return record
        except json.JSONDecodeError:
            logger.debug(f"Skipping malformed JSON line in {filepath}: {raw_line[:60]}")
            return None

    def run(self):
        logger.info(f"Starting Zeek ingestion daemon. Watching directory: {self.log_dir}")
        logger.info(f"Target topic: {self.topic}, Dry Run: {self.dry_run}")
        
        event_count = 0
        last_metric_time = time.time()

        try:
            while True:
                self.discover_logs()
                records_in_loop = 0

                for filepath, tailer in list(self.tailers.items()):
                    log_type = get_log_type_from_filename(filepath)
                    for line in tailer.read_lines():
                        record = self.process_record(line, log_type, filepath)
                        if record:
                            records_in_loop += 1
                            event_count += 1
                            flow_id = record.get("uid") or record.get("id.orig_h", "default")
                            
                            if self.dry_run:
                                print(f"[DRY-RUN] -> {self.topic}: {json.dumps(record)[:120]}...")
                            else:
                                self.producer.send(
                                    self.topic,
                                    key=flow_id,
                                    value=record,
                                )

                now = time.time()
                if now - last_metric_time >= 5.0:
                    rate = event_count / (now - last_metric_time)
                    logger.info(f"Ingested {event_count} total events ({rate:.1f} events/sec)")
                    event_count = 0
                    last_metric_time = now

                if records_in_loop == 0:
                    time.sleep(self.poll_interval)
                else:
                    if self.producer and not self.dry_run:
                        self.producer.flush()

        except KeyboardInterrupt:
            logger.info("Ingestion daemon interrupted by user. Shutting down...")
        finally:
            if self.producer:
                self.producer.flush()
                self.producer.close()
            logger.info("Ingestion shutdown complete.")


def parse_args():
    parser = argparse.ArgumentParser(description="Tail Zeek JSON logs to Redpanda raw_traffic topic.")
    parser.add_argument("--broker", default="localhost:9092", help="Redpanda / Kafka bootstrap broker host:port")
    parser.add_argument("--topic", default="raw_traffic", help="Destination Kafka topic")
    parser.add_argument("--log-dir", default="data/zeek_logs", help="Directory containing Zeek logs")
    parser.add_argument("--poll-interval", type=float, default=0.05, help="Poll interval in seconds when idle")
    parser.add_argument("--from-beginning", action="store_true", help="Read existing logs from start")
    parser.add_argument("--dry-run", action="store_true", help="Print records instead of sending to Redpanda")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    ingestor = ZeekToRedpandaIngestor(
        bootstrap_servers=args.broker,
        topic=args.topic,
        log_dir=args.log_dir,
        poll_interval=args.poll_interval,
        from_beginning=args.from_beginning,
        dry_run=args.dry_run,
    )
    ingestor.run()
