#!/usr/bin/env bash
# backup_postgres.sh -- dumps the TSOC Postgres database to a timestamped,
# custom-format (pg_dump -Fc) archive suitable for restore_postgres.sh.
#
# Reads DATABASE_URL the same way api/database.py and every other script
# in this repo does -- a plain postgresql://user:pass@host:port/dbname
# URI. pg_dump accepts this as a connection string directly via libpq,
# so no manual host/port/user parsing is needed here.
#
# See docs/DISASTER_RECOVERY.md for the retention policy and restore
# procedure this feeds into.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set (postgresql://user:pass@host:port/dbname)}"

BACKUP_DIR="${BACKUP_DIR:-$(cd "$(dirname "$0")/.." && pwd)/backups}"
mkdir -p "$BACKUP_DIR"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="${BACKUP_FILE:-$BACKUP_DIR/tsoc-$TIMESTAMP.dump}"

# Progress on stderr, not stdout -- lets a caller capture just the backup
# path with BACKUP_FILE=$(scripts/backup_postgres.sh).
echo "==> Backing up database to $BACKUP_FILE" >&2
pg_dump "$DATABASE_URL" -Fc -f "$BACKUP_FILE"
echo "==> Done ($(du -h "$BACKUP_FILE" | cut -f1))." >&2

echo "$BACKUP_FILE"
