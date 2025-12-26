#!/usr/bin/env bash
set -euo pipefail

# DB backup script for SF
# - Loads .env.production if present
# - Runs pg_dump against $DATABASE_URL
# - Compresses output
# - Rotates local backups (keep 7 days)
# - Optionally uploads to S3 if AWS_S3_BUCKET is set and `aws` CLI available

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env.production"
BACKUP_DIR="/backups"
KEEP_DAYS=7

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

mkdir -p "$BACKUP_DIR"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILENAME="sfdb-${TIMESTAMP}.sql.gz"
OUTPATH="$BACKUP_DIR/$FILENAME"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL not set. Aborting." >&2
  exit 1
fi

echo "Starting DB backup to $OUTPATH"

# Use pg_dump with connection string and gzip
if command -v pg_dump >/dev/null 2>&1; then
  pg_dump "$DATABASE_URL" | gzip > "$OUTPATH"
else
  echo "pg_dump not found in PATH" >&2
  exit 1
fi

echo "Backup complete: $OUTPATH"

if [ -n "${AWS_S3_BUCKET:-}" ] && command -v aws >/dev/null 2>&1; then
  echo "Uploading to s3://$AWS_S3_BUCKET/"
  aws s3 cp "$OUTPATH" "s3://$AWS_S3_BUCKET/" --acl private
  if [ $? -eq 0 ]; then
    echo "Upload successful"
  else
    echo "Upload failed" >&2
  fi
fi

echo "Rotating local backups (keeping ${KEEP_DAYS} days)"
find "$BACKUP_DIR" -type f -name 'sfdb-*.sql.gz' -mtime +$KEEP_DAYS -print -delete || true

echo "Done."
