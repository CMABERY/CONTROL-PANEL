# CPO Governance Kernel

A PostgreSQL-native governance kernel that enforces correctness through structure, not vigilance.

## Operational Mantra

```
Authority is authenticated.
Physics outranks policy.
Enumerations are structural.
Evaluation is closed-world.
Exceptions are expiring authority.
Drift becomes ledger artifacts.
Change control governs the rules.
Every commit re-proves the world.
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     cpo.commit_action()                              │
│                   (SINGLE WRITE APERTURE)                            │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │   Stage 1: Authenticate caller      │
         │   (DB role, not JSON)               │
         └──────────────────┬──────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │   Stage 2: Validate envelope        │
         └──────────────────┬──────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │   Stage 3: TOCTOU check             │
         │   (expected refs ALWAYS required)   │
         └──────────────────┬──────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │   Stage 4: Evaluate gates           │
         │   • Kernel-mandatory (P6)           │
         │   • Charter-defined                 │
         └──────────────────┬──────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │   Stage 5: Persist                  │
         │   • Action log (always)             │
         │   • Artifacts (if applied=true)     │
         └─────────────────────────────────────┘
```

## Phase Summary

| Phase | Name | Invariants | Status |
|-------|------|------------|--------|
| P1 | Policy Check Registry | INV-1xx | ✅ Complete |
| P2 | Write Aperture | INV-2xx | ✅ Complete |
| P3 | Gate Integration | INV-3xx | ✅ Complete |
| P4 | Exception Expiry | INV-4xx | ✅ Complete |
| P5 | Drift Detection | INV-5xx | ✅ Complete |
| P6 | Change Control | INV-6xx | ✅ Complete (v3.1) |
| P7 | Release Pipeline | INV-701 | ✅ Complete |

See `STATUS.json` for canonical evidence links.

## Key Invariants

### P3: No Semantic Privilege
```sql
-- PROHIBITED: action_type prefix privilege
IF v_action_type LIKE 'SYSTEM_%' THEN ...  -- NEVER

-- REQUIRED: DB role-based capability
v_capability := cpo.get_caller_capability();  -- Always
```

### P4: Exception Expiry
- `expiry_at <= now` ⇒ expired (knife-edge inclusive)
- `expiry_at IS NULL` ⇒ invalid (fail-closed)
- No zombie exceptions

### P6: Change Control as Physics
- Charter mutation requires `changes[]` artifact
- Approvals are deterministic with mandatory expiry
- Genesis exemption requires authenticated bootstrap context
- Replay blocked via unique indexes

## Running the Pipeline

```bash
export DATABASE_URL="postgres://user:pass@host:5432/dbname"

# Full P7 pipeline: fresh DB → migrate → guards → proofs → evidence
./scripts/p7_ci_pipeline.sh
```

### Pipeline Outputs

Generated under `./p7_artifacts/`:
- `evidence_pack.json` — DB-level fingerprints
- `manifest.json` — run metadata + log hashes
- `schema.sql` — schema dump (if pg_dump available)
- `logs/` — stdout/stderr for each step

## Deployment

### Apply P6 (Change Control)
```bash
./scripts/deploy_p6.sh "$DATABASE_URL"
```

### Apply P4 (Exception Expiry)
```bash
./scripts/deploy_p4.sh "$DATABASE_URL"
```

## Directory Structure

```
cpo/
├── sql/
│   ├── migrations/           # Core schema (006_, 009_)
│   ├── patches/              # Phase patches (p2_, p3_, p4_, p5_, p6_)
│   └── proofs/               # CI guards
├── scripts/
│   ├── p7_ci_pipeline.sh     # Release closure pipeline
│   ├── deploy_p4.sh          # P4 deployment
│   └── deploy_p6.sh          # P6 deployment
├── docs/                     # Phase summaries
└── STATUS.json               # Canonical status authority
```

## Strictness Properties

- `set -euo pipefail` everywhere
- Every `psql` uses `-v ON_ERROR_STOP=1`
- No SKIP branches: missing prerequisites hard-fail
- All proofs run the real write path with hard assertions
