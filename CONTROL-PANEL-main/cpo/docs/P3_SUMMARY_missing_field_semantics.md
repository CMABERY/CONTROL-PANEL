# P3 Missing-Field Semantics (Strict Everywhere)

This bundle implements the locked P3 semantic:

> Any rule that references a JSON pointer path implicitly requires that path.
> If the pointer resolves to missing/NULL (including JSON null), the gate returns **ERROR** (not FAIL), and the write is blocked.

## What changed

### 1) Required pointer resolver
A new function is introduced:

- `cpo.jsonptr_get_required(ctx jsonb, ptr text) -> jsonb`

It wraps the existing `cpo.jsonptr_get` and **raises** when:

- the path is missing (SQL NULL), or
- the value is JSON `null`.

Exception contract:

- `SQLSTATE = 'CPO01'`
- `MESSAGE_TEXT = 'MISSING_POINTER'`
- `PG_EXCEPTION_DETAIL = <pointer>`

This allows the gate engine to classify the error without string parsing.

### 2) Pointer operands are required
`cpo._resolve_arg(ctx, arg)` is updated:

- any string `arg` starting with `/` is treated as a pointer and resolved through `jsonptr_get_required`.

This enforces "strict everywhere" without changing operator semantics.

### 3) Gate engine classifies missing fields
`cpo.evaluate_gates(...)` is updated to normalize exceptions:

- when it catches `SQLSTATE='CPO01'` and `MESSAGE='MISSING_POINTER'`, it emits:

```json
{
  "status": "ERROR",
  "error_type": "MISSING_FIELD",
  "error_code": "MISSING_FIELD",
  "missing_pointer": "/resolved/state/..."
}
```

Any ERROR gate forces overall `outcome = FAIL` (write blocked), preserving fail-closed behavior.

## Files

- `p3_missing_field_semantics_patch.sql`
  - adds `jsonptr_get_required`
  - updates `_resolve_arg` to use it

- `p3_gate_engine_missing_field_patch.sql`
  - updates `evaluate_gates` to classify missing fields

- `p3_proof_missing_field_semantics.sql`
  - behavioral proof via `commit_action` (anchored to the write aperture)
  - asserts:
    - missing field => `ERROR` (not FAIL)
    - exceptions are not consulted on ERROR
    - artifacts are not written (`applied=false`)

## Apply order

1. Apply your existing P3 baseline (if not already):
   - `sql/007_policy_dsl.sql`
   - `sql/008_gate_engine.sql`
   - `sql/009_commit_action_gate_integration.sql`

2. Apply this bundle:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_missing_field_semantics_patch.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_gate_engine_missing_field_patch.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_missing_field_semantics.sql
```

## Notes

- This change is intentionally strict: it turns misconfigured gates into **ERROR** rather than a silent **FAIL**.
- If you later want "optional" fields, that should be expressed via explicit null-safe operators (e.g., `EXISTS`, `COALESCE`, `IS_NULL`) rather than by defaulting missing fields to false.
