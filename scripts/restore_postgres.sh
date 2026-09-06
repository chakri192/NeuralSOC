#!/usr/bin/env bash
# restore_postgres.sh -- restores a pg_dump -Fc archive produced by
# backup_postgres.sh.
#
# Destructive: --clean --if-exists drops existing objects before
# recreating them from the archive, so the target database ends up
# exactly matching the backup, not a merge of the two. Run this against
# the database you intend to actually replace, not a copy you also
# care about keeping as-is.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set (postgresql://user:pass@host:port/dbname)}"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <backup-file.dump>" >&2
    exit 1
fi
BACKUP_FILE="$1"
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Backup file not found: $BACKUP_FILE" >&2
    exit 1
fi

echo "==> Restoring $BACKUP_FILE into the database at DATABASE_URL" >&2
pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" "$BACKUP_FILE"
echo "==> Restore complete." >&2
