#!/usr/bin/env bash
set -euo pipefail

DB_URL="${1:-}"
if [[ -z "${DB_URL}" ]]; then
  echo "Usage: $0 \"$DATABASE_URL\"" >&2
  exit 2
fi

# P4 patch must be applied AFTER the gate engine and AFTER any earlier
# exception enforcement file that would override these functions.

psql "$DB_URL" -v ON_ERROR_STOP=1 -f p4_exception_expiry_enforcement_v3.sql
psql "$DB_URL" -v ON_ERROR_STOP=1 -f p4_exception_expiry_proofs_v3.sql

echo "P4 OK: exception expiry/authority patch applied and proofs passed."
