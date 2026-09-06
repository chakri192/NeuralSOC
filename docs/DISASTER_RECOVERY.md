# Disaster Recovery

Covers the two things that can actually be lost here: the Postgres
alerts database (`api/kafka_sink.py`'s sink target) and alerts stuck in
`api/kafka_sink.py`'s local-disk DLQ. Kafka/Redpanda topics themselves
are not covered by a separate backup procedure -- `raw_traffic`,
`security_alerts`, and `incidents` are all short-retention, high-volume
streams (see `scripts/create_topics.sh`) that are expected to be
transient by design; the durable record of a detection is the row it
becomes in Postgres, not the topic message that produced it.

## Postgres: backup and restore

**Schedule:** run `scripts/backup_postgres.sh` on a cron (daily is a
reasonable default for this data's change rate -- adjust to your actual
alert volume). It writes a timestamped `pg_dump -Fc` archive to
`$BACKUP_DIR` (defaults to `./backups`); ship that directory to
durable, off-host storage (S3/GCS/etc.) as part of the same job --
this repo doesn't own that transport, only the dump itself.

**Retention:** keep at least 7 daily archives and 4 weekly archives.
Alerts are append-mostly (kafka_sink.py's bulk upsert only ever
inserts new rows or updates an existing row's severity/evidence by
`alert_id`), so older backups stay useful for point-in-time
investigation, not just disaster recovery.

**Restore procedure:**
```bash
export DATABASE_URL=postgresql://user:pass@host:port/tsoc
scripts/restore_postgres.sh backups/tsoc-20260101T000000Z.dump
```
This is destructive (`pg_restore --clean --if-exists`) -- it replaces
every object in the target database with what's in the archive, not a
merge. Restore into a fresh database first if you need to verify an
archive without touching production.

**RTO / RPO:**
- **RPO (data loss window): up to 24 hours** with a daily backup
  schedule -- alerts ingested between the last backup and the incident
  are lost from Postgres, though they may still be recoverable from
  Redpanda's `security_alerts` topic if its retention window hasn't
  expired yet (see `scripts/create_topics.sh` for the configured
  retention per topic).
- **RTO (time to restore service): well under 30 minutes** for a
  database of the size this platform produces (alerts, not raw
  packets) -- dominated by `pg_restore`'s own runtime, not manual
  steps. Tighten the backup schedule (e.g. hourly) if your actual RPO
  requirement is stricter than daily.

Neither figure has been measured against a production-scale dataset;
both are engineering estimates based on the schema and pipeline as
built here, not a benchmarked SLA.

## Kafka DLQ replay

`api/kafka_sink.py` routes an alert to its local-disk DLQ
(`DLQ_FILE_PATH`, default `/tmp/dlq/alerts.jsonl`) when it fails
processing -- a database outage, a transient bulk-upsert failure that
also fails its per-item fallback, or a schema-invalid payload. These
alerts are **not** automatically retried; they sit on disk until an
operator acts.

**Investigate first.** A DLQ file growing steadily is exactly what
`k8s/prometheus-rules.yaml`'s `KafkaSinkDlqGrowing` alert watches for
-- find and fix the underlying cause (check the sink's own logs for
`"Bulk upsert failed"` / `"Batch DB commit failure"`) before replaying,
or you'll just refill the DLQ with the same failures.

**Replay:**
```bash
# See what would be replayed without publishing anything:
python scripts/replay_dlq.py --dry-run

# Actually replay, then archive the DLQ file (rename, not delete --
# --archive-after only runs after a full, unfiltered replay):
python scripts/replay_dlq.py --archive-after
```
Replayed alerts go back through the real consumer (`api/kafka_sink.py`),
including its existing validation and bulk-upsert idempotency -- an
alert that already made it to Postgres before failing on a *later*
step of the same batch is safely re-upserted, not duplicated, since the
sink matches on `alert_id`.

Correlation state (`inference/correlation.py`, Redis) is never touched
by this replay path -- kafka_sink.py's DLQ only ever holds alerts that
failed *after* the stream-processor's own correlation step already ran
against them, so there's nothing to roll back or re-coordinate here.

## Genuinely out of scope here

- **A tested backup/restore cycle against a production-scale dataset.**
  The mechanism is proven correct (see CI's `backup-restore-drill` job,
  which does a real create-data → backup → wipe → restore → verify
  cycle on every push) but only against a small, synthetic table -- not
  benchmarked at real production alert volume.
- **Kafka/Redpanda topic-level backup.** As noted above, these topics
  are deliberately short-retention and transient by design; Postgres is
  the durable record.
- **Automated, unattended DLQ replay.** Deliberately a human-run tool,
  not a cron job -- see the reasoning in `scripts/replay_dlq.py`'s own
  module docstring.
