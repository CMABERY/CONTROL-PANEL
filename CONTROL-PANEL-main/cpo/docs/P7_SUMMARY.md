# P7 — Release-Grade Closure Pipeline (INV-701)

## Locked invariant

**INV-701**: A commit is not shippable unless a fresh database can run migrations,
pass P0–P6 proofs, and pass durability round-trip verification.

## What this bundle provides

- `p7_ci_pipeline.sh` — one-command pipeline:
  1. creates a fresh database
  2. applies migrations
  3. runs privilege audit + optional CI guards
  4. runs all discovered proofs (selftests + proof scripts)
  5. requires at least one durability-related proof to run
  6. generates an evidence pack JSON + manifest + (optional) schema dump hash

- `p7_privilege_audit.sql` — hard-fails on privilege drift:
  - PUBLIC EXECUTE on any `cpo` function
  - PUBLIC DML on any `cpo` table
  - SECURITY DEFINER functions missing `SET search_path` lock

- `p7_evidence_pack.sql` — emits JSON including:
  - run metadata
  - per-function SHA256 hashes for all functions in schema `cpo`
  - aggregate SHA256 fingerprint of those function hashes
  - basic PUBLIC privilege counts (mirrors privilege audit)

## Usage

### Minimal

```bash
export DATABASE_URL="postgres://..."
./p7_ci_pipeline.sh
```

### With explicit admin URL

```bash
export DATABASE_URL="postgres://user:pass@host:5432/some_db"
export P7_ADMIN_DATABASE_URL="postgres://user:pass@host:5432/postgres"
./p7_ci_pipeline.sh
```

### With explicit file selection (recommended)

```bash
export P7_SQL_DIR="./sql"
export P7_MIGRATION_GLOBS="./sql/[0-9][0-9][0-9]_*.sql"
export P7_PROOF_GLOBS="./sql/**/*selftest*.sql ./sql/**/*proof*.sql"
export P7_GUARD_GLOBS="./sql/**/*ci_guard*.sql"
./p7_ci_pipeline.sh
```

## Determinism / No false-green

- `set -euo pipefail`
- every `psql` call uses `-v ON_ERROR_STOP=1`
- all outputs captured; on failure last 80 lines are printed
- no SKIP branches: missing prerequisites hard-fail

## Evidence artifacts

Generated under `./p7_artifacts/` by default:

- `evidence_pack.json` — DB-level fingerprints (sha256 of `cpo` function defs, etc.)
- `manifest.json` — run metadata + sha256 of log files (+ optional schema hash)
- `logs/` — stdout/stderr for each migration/guard/proof step
- `schema.sql` — only if `pg_dump` is available (hashed into manifest)

## Known repo-specific customization points

This bundle discovers files via globs. For kernel-grade releases, prefer explicit globs or a manifest-driven ordering.

- If your repo requires an exact migration order beyond lexicographic sorting, set `P7_MIGRATION_GLOBS` and/or split migrations into multiple passes.
- If some proofs require roles (e.g., `cpo_migration`, `cpo_bootstrap`), ensure CI runs with those memberships. The pipeline will **fail**, not skip, if the proofs hard-fail.

