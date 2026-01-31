#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
shopt -s nullglob globstar

# ==============================================================================
# P7 CI Pipeline — Release-grade closure (INV-701)
#
# Goal: Fresh DB -> migrate -> guards -> proofs -> durability round-trip -> evidence
#
# Strictness:
#   - set -euo pipefail
#   - every psql uses -v ON_ERROR_STOP=1
#   - outputs captured to logs; on failure tail logs
#   - no "SKIP" branches: missing prerequisites => hard fail
#
# Config (env):
#   DATABASE_URL                Required. Base connection URL (any DB on target cluster)
#   P7_ADMIN_DATABASE_URL       Optional. Admin URL (defaults to DATABASE_URL with /postgres)
#   P7_SQL_DIR                  Optional. Default: ./sql
#   P7_LOG_DIR                  Optional. Default: ./p7_artifacts/logs
#   P7_EVIDENCE_DIR             Optional. Default: ./p7_artifacts
#   P7_DB_PREFIX                Optional. Default: cpo_p7_ci
#   P7_RUN_ID                   Optional. Default: timestamp + random
#   P7_GUARD_GLOBS              Optional. Space-separated globs. Default: "" (none)
#   P7_MIGRATION_GLOBS          Optional. Default: "$P7_SQL_DIR/[0-9][0-9][0-9]_*.sql"
#   P7_PROOF_GLOBS              Optional. Default: "$P7_SQL_DIR/**/*selftest*.sql $P7_SQL_DIR/**/*proof*.sql"
#   P7_REQUIRE_DURABILITY_GLOB  Optional. Default: "*durability*"
#   P7_COMMIT_SHA               Optional. Included in evidence pack metadata
#
# Exit codes:
#   0 success
#   nonzero failure (tails relevant logs)
# ==============================================================================

die() { echo "P7 FAIL: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
need_cmd psql
need_cmd python3

: "${DATABASE_URL:?DATABASE_URL is required}"

P7_SQL_DIR="${P7_SQL_DIR:-./sql}"
P7_EVIDENCE_DIR="${P7_EVIDENCE_DIR:-./p7_artifacts}"
P7_LOG_DIR="${P7_LOG_DIR:-$P7_EVIDENCE_DIR/logs}"
P7_DB_PREFIX="${P7_DB_PREFIX:-cpo_p7_ci}"

P7_RUN_ID="${P7_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM}"
mkdir -p "$P7_LOG_DIR"

# -------- helpers --------
psql_strict() {
  local url="$1"; shift
  # -X: no ~/.psqlrc; -v ON_ERROR_STOP=1: fail on first error
  psql "$url" -X -v ON_ERROR_STOP=1 "$@"
}

run_sql() {
  local url="$1"
  local file="$2"
  local name="${3:-$(basename "$file")}"
  local log="$P7_LOG_DIR/$name.log"
  echo "==> RUN $name"
  # capture full log; show tail on failure
  if ! psql_strict "$url" -f "$file" >"$log" 2>&1; then
    echo "---- last 80 lines: $log ----" >&2
    tail -n 80 "$log" >&2 || true
    die "$name failed"
  fi
}

run_sql_inline() {
  local url="$1"
  local name="$2"
  local sql="$3"
  local log="$P7_LOG_DIR/$name.log"
  echo "==> RUN $name"
  if ! psql_strict "$url" -c "$sql" >"$log" 2>&1; then
    echo "---- last 80 lines: $log ----" >&2
    tail -n 80 "$log" >&2 || true
    die "$name failed"
  fi
}

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    python3 - <<'PY' "$f"
import hashlib,sys
p=sys.argv[1]
h=hashlib.sha256()
with open(p,'rb') as fp:
  for chunk in iter(lambda: fp.read(1024*1024), b''):
    h.update(chunk)
print(h.hexdigest())
PY
  fi
}

# -------- create fresh DB --------
P7_TEMP_DB="${P7_DB_PREFIX}_${P7_RUN_ID//[^A-Za-z0-9_]/_}"

# default admin url = same as DATABASE_URL but db=postgres
P7_ADMIN_DATABASE_URL="${P7_ADMIN_DATABASE_URL:-$(
python3 - <<'PY'
import os, urllib.parse
u=os.environ['DATABASE_URL']
p=urllib.parse.urlparse(u)
# if url has no path, add /postgres
new=urllib.parse.urlunparse(p._replace(path='/postgres'))
print(new)
PY
)}"

P7_TEST_DATABASE_URL="$(
python3 - <<'PY'
import os, urllib.parse
base=os.environ['DATABASE_URL']
db=os.environ['P7_TEMP_DB']
p=urllib.parse.urlparse(base)
# keep query/fragment; replace path
new=urllib.parse.urlunparse(p._replace(path='/' + db))
print(new)
PY
)"

echo "==> P7 RUN_ID: $P7_RUN_ID"
echo "==> Creating fresh database: $P7_TEMP_DB"

run_sql_inline "$P7_ADMIN_DATABASE_URL" "p7_create_db" "DROP DATABASE IF EXISTS \"$P7_TEMP_DB\"; CREATE DATABASE \"$P7_TEMP_DB\";"

cleanup() {
  local ec=$?
  echo "==> Cleanup: dropping database $P7_TEMP_DB"
  # Don't mask original failure if drop fails
  psql_strict "$P7_ADMIN_DATABASE_URL" -c "DROP DATABASE IF EXISTS \"$P7_TEMP_DB\";" >/dev/null 2>&1 || true
  exit $ec
}
trap cleanup EXIT

# -------- migrations --------
MIG_GLOBS="${P7_MIGRATION_GLOBS:-$P7_SQL_DIR/[0-9][0-9][0-9]_*.sql}"
MIG_FILES=()
for g in $MIG_GLOBS; do
  for f in $g; do MIG_FILES+=("$f"); done
done
# filter out selftests / proofs
MIG_FILES=( $(printf "%s\n" "${MIG_FILES[@]}" | grep -v -E '(selftest|proof|ci_guard)' | sort -V) )

[[ ${#MIG_FILES[@]} -gt 0 ]] || die "no migration files found via P7_MIGRATION_GLOBS='$MIG_GLOBS' (dir: $P7_SQL_DIR)"

echo "==> Applying migrations (${#MIG_FILES[@]} files)"
for f in "${MIG_FILES[@]}"; do
  [[ -f "$f" ]] || die "migration file not found: $f"
  run_sql "$P7_TEST_DATABASE_URL" "$f" "migrate_$(basename "$f")"
done

# -------- guards (structural + privilege) --------
# p7_privilege_audit.sql is expected alongside this script or in repo; try both.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIV_AUDIT_CANDIDATES=(
  "$SCRIPT_DIR/p7_privilege_audit.sql"
  "$P7_SQL_DIR/p7_privilege_audit.sql"
)
PRIV_AUDIT=""
for c in "${PRIV_AUDIT_CANDIDATES[@]}"; do
  if [[ -f "$c" ]]; then PRIV_AUDIT="$c"; break; fi
done
[[ -n "$PRIV_AUDIT" ]] || die "p7_privilege_audit.sql not found (looked in $SCRIPT_DIR and $P7_SQL_DIR)"

run_sql "$P7_TEST_DATABASE_URL" "$PRIV_AUDIT" "guard_privilege_audit"

# Optional additional guards (user-provided)
GUARD_GLOBS="${P7_GUARD_GLOBS:-}"
if [[ -n "$GUARD_GLOBS" ]]; then
  GUARD_FILES=()
  for g in $GUARD_GLOBS; do
    for f in $g; do GUARD_FILES+=("$f"); done
  done
  GUARD_FILES=( $(printf "%s\n" "${GUARD_FILES[@]}" | sort -V) )
  echo "==> Running guards (${#GUARD_FILES[@]} files)"
  for f in "${GUARD_FILES[@]}"; do
    [[ -f "$f" ]] || die "guard file not found: $f"
    run_sql "$P7_TEST_DATABASE_URL" "$f" "guard_$(basename "$f")"
  done
else
  echo "==> No extra guards configured (P7_GUARD_GLOBS empty)"
fi

# -------- proofs --------
PROOF_GLOBS="${P7_PROOF_GLOBS:-$P7_SQL_DIR/**/*selftest*.sql $P7_SQL_DIR/**/*proof*.sql}"
PROOF_FILES=()
for g in $PROOF_GLOBS; do
  for f in $g; do PROOF_FILES+=("$f"); done
done
PROOF_FILES=( $(printf "%s\n" "${PROOF_FILES[@]}" | sort -V) | awk '!seen[$0]++' )

[[ ${#PROOF_FILES[@]} -gt 0 ]] || die "no proof files found via P7_PROOF_GLOBS='$PROOF_GLOBS'"

# Require durability presence
REQ_DUR="${P7_REQUIRE_DURABILITY_GLOB:-durability}"
if ! printf "%s\n" "${PROOF_FILES[@]}" | grep -qi "$REQ_DUR"; then
  die "durability proof missing: none of the discovered proofs match /$REQ_DUR/i. Set P7_REQUIRE_DURABILITY_GLOB to adjust."
fi

echo "==> Running proofs (${#PROOF_FILES[@]} files)"
for f in "${PROOF_FILES[@]}"; do
  [[ -f "$f" ]] || die "proof file not found: $f"
  run_sql "$P7_TEST_DATABASE_URL" "$f" "proof_$(basename "$f")"
done

# -------- evidence pack --------
mkdir -p "$P7_EVIDENCE_DIR"
MANIFEST="$P7_EVIDENCE_DIR/manifest.json"
EVIDENCE_JSON="$P7_EVIDENCE_DIR/evidence_pack.json"

# SQL evidence pack
EVID_SQL_CANDIDATES=(
  "$SCRIPT_DIR/p7_evidence_pack.sql"
  "$P7_SQL_DIR/p7_evidence_pack.sql"
)
EVID_SQL=""
for c in "${EVID_SQL_CANDIDATES[@]}"; do
  if [[ -f "$c" ]]; then EVID_SQL="$c"; break; fi
done
[[ -n "$EVID_SQL" ]] || die "p7_evidence_pack.sql not found (looked in $SCRIPT_DIR and $P7_SQL_DIR)"

echo "==> Generating DB evidence pack JSON"
if ! psql_strict "$P7_TEST_DATABASE_URL" -f "$EVID_SQL" -v p7_run_id="'$P7_RUN_ID'" -v p7_commit_sha="'${P7_COMMIT_SHA:-}'" >"$EVIDENCE_JSON" 2>"$P7_LOG_DIR/evidence_pack.stderr.log"; then
  echo "---- stderr ----" >&2
  tail -n 80 "$P7_LOG_DIR/evidence_pack.stderr.log" >&2 || true
  die "evidence pack SQL failed"
fi

# schema dump hash if pg_dump exists
SCHEMA_HASH=""
if command -v pg_dump >/dev/null 2>&1; then
  SCHEMA_SQL="$P7_EVIDENCE_DIR/schema.sql"
  echo "==> Capturing schema dump via pg_dump --schema-only"
  if ! pg_dump "$P7_TEST_DATABASE_URL" --schema-only --no-owner --no-privileges >"$SCHEMA_SQL" 2>"$P7_LOG_DIR/pg_dump.stderr.log"; then
    echo "---- pg_dump stderr ----" >&2
    tail -n 80 "$P7_LOG_DIR/pg_dump.stderr.log" >&2 || true
    die "pg_dump failed"
  fi
  SCHEMA_HASH="$(sha256_file "$SCHEMA_SQL")"
fi

echo "==> Writing manifest"
python3 - <<'PY' "$MANIFEST" "$P7_RUN_ID" "$P7_COMMIT_SHA" "$P7_TEMP_DB" "$SCHEMA_HASH"
import json,sys,os,glob,hashlib
manifest_path, run_id, commit_sha, dbname, schema_hash = sys.argv[1:]
def sha256(p):
  h=hashlib.sha256()
  with open(p,'rb') as fp:
    for chunk in iter(lambda: fp.read(1024*1024), b''):
      h.update(chunk)
  return h.hexdigest()
files = []
for root,_,names in os.walk(os.path.join(os.environ.get("P7_EVIDENCE_DIR","./p7_artifacts"),"logs")):
  for n in names:
    p=os.path.join(root,n)
    files.append({"path": os.path.relpath(p, os.environ.get("P7_EVIDENCE_DIR","./p7_artifacts")), "sha256": sha256(p)})
out = {
  "run_id": run_id,
  "commit_sha": commit_sha or None,
  "dbname": dbname,
  "generated_at_utc": __import__("datetime").datetime.utcnow().isoformat()+"Z",
  "schema_sha256": schema_hash or None,
  "logs": sorted(files, key=lambda x: x["path"]),
}
with open(manifest_path,"w",encoding="utf-8") as f:
  json.dump(out,f,indent=2,sort_keys=True)
print("OK:", manifest_path)
PY

echo "==> P7 PASS: INV-701 satisfied for run $P7_RUN_ID"
echo "Artifacts:"
echo "  - $EVIDENCE_JSON"
echo "  - $MANIFEST"
if [[ -n "$SCHEMA_HASH" ]]; then echo "  - schema.sql (sha256=$SCHEMA_HASH)"; fi
