# P4 — Exception expiry & authority

P4 treats exceptions as **time-bounded authority**, not escape hatches.

## Locked invariants

- **INV-401**: Exceptions apply only to **FAIL** (never to ERROR).
- **INV-402**: `expiry_at <= now` ⇒ expired (inclusive knife-edge).
- **INV-403**: `expiry_at IS NULL` ⇒ invalid (fail-closed).
- **INV-404**: `PASS_WITH_EXCEPTION` records `exception_id` + `policy_check_id`.
- **INV-405**: Deterministic selection.
- **INV-406**: Kernel gates cannot be exceptioned (preserved by topology).

## What changed in v3

### 1) No zombie exceptions
`find_valid_exception(...)` now resolves **current** exception state by collapsing the append-only exception ledger to the **latest row per `exception_id`**. This prevents an older ACTIVE row from re-applying after a later REVOKED row.

### 2) Expiry is mandatory and strict
- Missing `expiry_at` ⇒ invalid.
- `expiry_at <= now` ⇒ invalid.

### 3) Deterministic selection (and ambiguity fails closed)
If more than one valid exception matches the same `(agent_id, policy_check_id, action_type)` at evaluation time, resolution raises an error (write blocked). This prevents ambiguous authority.

## Files

- `p4_exception_expiry_enforcement_v3.sql` — runtime patch (`is_exception_valid`, `find_valid_exception`).
- `p4_exception_expiry_proofs_v3.sql` — hard-assert proof suite.
- `deploy_p4.sh` — strict deploy runner.

## Apply order

Run the patch **after** the gate engine (and after any earlier exception enforcement file that would otherwise override it).

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/008_gate_engine.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/010_exception_expiry_enforcement.sql  # if present
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p4_exception_expiry_enforcement_v3.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p4_exception_expiry_proofs_v3.sql
```
