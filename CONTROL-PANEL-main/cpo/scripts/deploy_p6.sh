#!/usr/bin/env bash
set -euo pipefail

DB_URL="${1:-}"
if [[ -z "${DB_URL}" ]]; then
  echo "usage: ./deploy_p6.sh \"$DATABASE_URL\"" >&2
  exit 2
fi

run() {
  local f="$1"
  echo "[P6] applying: $f" >&2
  psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$f"
}

run "p6_change_control_kernel_patch.sql"
run "p6_change_control_proofs.sql"
run "p6_ci_guard_change_control.sql"

echo "[P6] OK" >&2
