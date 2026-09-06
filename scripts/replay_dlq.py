#!/usr/bin/env python3
"""replay_dlq.py -- re-publishes alerts from api/kafka_sink.py's local-disk
DLQ (JSONL: one {"error", "alert", "timestamp"} object per line, written by
write_to_file_dlq()) back onto the Kafka alerts topic, giving them another
pass through the real consumer (validation + bulk upsert) instead of sitting
unrecovered on disk forever.

This is deliberately a separate, operator-run tool rather than something
kafka_sink.py does automatically: a DLQ exists specifically to isolate
alerts that failed processing from the healthy stream, and auto-replay
would risk a poison-pill item looping forever. A human decides when to
run this, typically after fixing whatever caused the underlying failures
(see docs/DISASTER_RECOVERY.md).

Only republishes to Kafka -- correlation state (inference/correlation.py)
is a stream-processor concern that never touches kafka_sink.py's DLQ, so
there's nothing to roll back or coordinate here.
"""
import argparse
import json
import logging
import os
import sys
import time

from kafka import KafkaProducer

logger = logging.getLogger("replay_dlq")


def _default_dlq_path():
    # Mirrors api/kafka_sink.py's own default -- not importing that module
    # directly since it constructs a live KafkaConsumer at import time
    # (see run_sink()), which this read-only/producer-only tool has no
    # need to pull in.
    return os.getenv("DLQ_FILE_PATH", "/tmp/dlq/alerts.jsonl")  # nosec B108


def load_dlq_entries(dlq_path):
    """Yields (line_number, entry_dict) for each parseable line; logs and
    skips (rather than aborting the whole replay on) a malformed line."""
    with open(dlq_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("Skipping unparseable DLQ line %d: %s", line_number, e)
                continue
            if not isinstance(entry, dict) or "alert" not in entry:
                logger.warning("Skipping DLQ line %d: missing 'alert' field", line_number)
                continue
            yield line_number, entry


def replay(dlq_path, brokers, topic, dry_run=False, limit=None):
    entries = list(load_dlq_entries(dlq_path))
    if limit is not None:
        entries = entries[:limit]

    if dry_run:
        for line_number, entry in entries:
            alert_id = entry["alert"].get("alert_id", "<unknown>") if isinstance(entry["alert"], dict) else "<unknown>"
            print(f"[DRY RUN] would replay line {line_number}: alert_id={alert_id}, original_error={entry.get('error')}")
        return len(entries)

    producer = KafkaProducer(
        bootstrap_servers=[b.strip() for b in brokers.split(",") if b.strip()],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5,
    )
    replayed = 0
    try:
        for line_number, entry in entries:
            producer.send(topic, entry["alert"])
            replayed += 1
        producer.flush(timeout=30)
    finally:
        producer.close()
    return replayed


def main():
    parser = argparse.ArgumentParser(description="Replay api/kafka_sink.py's local-disk DLQ back onto the alerts topic")
    parser.add_argument("--dlq-file", default=_default_dlq_path(), help="Path to the DLQ JSONL file")
    parser.add_argument("--brokers", default=os.getenv("REDPANDA_BROKERS", "localhost:9092"))
    parser.add_argument("--topic", default=os.getenv("ALERTS_TOPIC", "security_alerts"))
    parser.add_argument("--dry-run", action="store_true", help="Print what would be replayed without publishing")
    parser.add_argument("--limit", type=int, default=None, help="Replay at most this many entries")
    parser.add_argument(
        "--archive-after", action="store_true",
        help="Rename the DLQ file (append .replayed-<timestamp>) after a successful full replay, rather than leaving it in place",
    )
    args = parser.parse_args()

    if not os.path.exists(args.dlq_file):
        print(f"No DLQ file at {args.dlq_file} -- nothing to replay.")
        return 0

    count = replay(args.dlq_file, args.brokers, args.topic, dry_run=args.dry_run, limit=args.limit)
    print(f"{'Would replay' if args.dry_run else 'Replayed'} {count} alert(s) from {args.dlq_file} to topic {args.topic}.")

    if args.archive_after and not args.dry_run and args.limit is None:
        archived_path = f"{args.dlq_file}.replayed-{int(time.time())}"
        os.rename(args.dlq_file, archived_path)
        print(f"Archived DLQ file to {archived_path}.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
