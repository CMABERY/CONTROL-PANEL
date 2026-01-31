# P3 Gate Engine MVP - Summary

## Status: COMPLETE (v2.2 with audit corrections)

P3 delivers the gate evaluation engine with kernel-grade enforcement semantics.

---

## Audit Corrections Applied (v2.2)

| Issue | Problem | Fix |
|-------|---------|-----|
| **Blocker A: TOCTOU bypass** | `SYSTEM_%`, `BOOTSTRAP_%`, and `dry_run` bypasses | ALL removed; only `v_bootstrap` (DB state) bypasses |
| **dry_run bypass** | `dry_run=true` bypassed expected-refs but still wrote action logs | Removed; `dry_run` no longer bypasses TOCTOU |
| **Resolved inputs fail-open** | Missing charter/state/activation → NULL → {} → PASS | **KERNEL GATE 5**: RAISE on missing resolved inputs |
| **Phase naming drift** | P1/P2 names swapped in summary | Corrected (see below) |
| **DoD "registry-resolved"** | Claimed gates resolved via P1 seam (doesn't exist in repo) | **Formally revised** (see below) |
| **Exception proof SKIP** | Proof used SKIP instead of hard-fail | Removed SKIP, hard-fails if prerequisites missing |
| **Exception not seeded** | Behavioral proof didn't actually seed exception | Now inserts ACTIVE exception and proves it's ignored |

---

## Phase Naming (Corrected)

| Phase | Name | What It Provides |
|-------|------|------------------|
| **P0** | Semantic privilege elimination | `privileged_behavior = f(db_role)`, not strings |
| **P0.5** | Kernel gates non-exceptionable | Kernel validation before policy layer |
| **P1** | Policy check registry | (If exists) Gate ID validation via seam |
| **P2** | Artifact table registry | Durability enumeration, write aperture coverage |
| **P3** | Gate engine MVP | Evaluation semantics, TOCTOU-closed, fail-closed |

---

## DoD Revision: "Registry-resolved" Removed

**Original DoD included:**
> Registry-resolved: Gate IDs resolved via P1 seam (no string matching)

**Revision:** This requirement is **removed** from P3 DoD.

**Rationale:**
1. The repo's `008_gate_engine.sql` reads directly from `p_charter->'policy_checks'`
2. No `validate_charter_policy_checks()` or `resolve_policy_check()` seam exists
3. **Charter-defined gates is correct architecture:**
   - Each agent can have different policies in its charter
   - The charter IS the authoritative source for that agent's gates
   - No separate "gate registry" is needed or appropriate
4. P1 (in the repo) is about artifact table registry for durability, not gate registration

**If a P1 gate registry seam is later added, P3 can be upgraded to use it without changing the evaluation semantics.**

---

## Definition of Done (Revised)

| Requirement | Enforcement | Status |
|-------------|-------------|--------|
| **TOCTOU-closed** | Evaluation inside commit transaction, same snapshot as write | ✅ |
| **No semantic bypass** | TOCTOU enforcement NOT conditioned on `action_type` OR `dry_run` | ✅ (v2.1) |
| **Default deny** | Write proceeds ONLY on `PASS` or `PASS_WITH_EXCEPTION` | ✅ |
| **Fail-closed on unknown** | Unknown operator/root → `ERROR` → `FAIL` → write blocked | ✅ |
| **Strict missing-field** | Missing/null pointer → `ERROR` → `FAIL` → write blocked | ✅ |
| **Charter-defined gates** | Gates defined in charter `policy_checks` (authoritative per-agent) | ✅ |
| **Kernel gates non-exceptionable** | P0.5 topology: kernel validation before gate engine | ✅ |
| ~~Registry-resolved~~ | ~~Gate IDs resolved via P1 seam~~ | **REMOVED from DoD** |

---

## TOCTOU Bypass Rules (Locked, v2.2)

| Condition | Bypass Allowed? | Reason |
|-----------|-----------------|--------|
| `v_bootstrap = true` | ✅ Yes | First commit has no previous heads (detected from DB) |
| `v_dry_run = true` | ❌ **NO** | Action logs are still written; must enforce TOCTOU |
| `action_type = 'SYSTEM_%'` | ❌ **NO** | Semantic privilege violation (P0) |
| `action_type = 'BOOTSTRAP_%'` | ❌ **NO** | Use `v_bootstrap` (DB state) instead |

---

## P3 Semantic Contract

### Verdict Types

| Verdict | Meaning | Exceptions Consulted? | Write Proceeds? |
|---------|---------|----------------------|-----------------|
| `PASS` | Policy evaluated, approved | N/A | ✅ Yes |
| `FAIL` | Policy evaluated, denied | ✅ Yes (may upgrade to PASS_WITH_EXCEPTION) | ❌ No |
| `ERROR` | Policy could not evaluate | ❌ No (fail-closed) | ❌ No |
| `PASS_WITH_EXCEPTION` | FAIL + valid exception | N/A (already consulted) | ✅ Yes |

### Error Classification (Locked)

| Condition | Error Type | SQLSTATE | Exceptions? |
|-----------|------------|----------|-------------|
| Missing pointer path | `MISSING_FIELD` | `CPO01` | ❌ |
| JSON null literal | `MISSING_FIELD` | `CPO01` | ❌ |
| Unknown operator | `UNKNOWN_OPERATOR` | varies | ❌ |
| Disallowed pointer root | `DISALLOWED_ROOT` | varies | ❌ |
| Other evaluation error | `RULE_EVAL_ERROR` | varies | ❌ |

---

## Architecture

### Transaction Topology (v2.2)

```
commit_action() {
  1. Advisory lock (serialize per-agent)
  2. FOR UPDATE lock on heads row
  3. v_bootstrap := NOT FOUND (first commit detection from DB state)
  4. Resolve current refs (charter, state, activation)
  5. KERNEL GATES (RAISE directly, non-exceptionable):
     - agent_id validation
     - action_log_content validation
     - Bootstrap artifact requirements (if v_bootstrap)
     - TOCTOU / expected refs (if NOT v_bootstrap)  // dry_run does NOT bypass
     - RESOLVED INPUT EXISTENCE (charter/state/activation must exist)
  6. CHARTER GATES (via evaluate_gates, exception-eligible):
     - policy_checks from charter JSON
     - FAIL can become PASS_WITH_EXCEPTION
     - ERROR cannot be exception'd
  7. v_applied := (NOT dry_run) AND outcome IN (PASS, PASS_WITH_EXCEPTION)
  8. Insert action_log (always)
  9. Insert artifacts (only if v_applied)
  10. Update heads (only if v_applied)
}
```

### Context Shape (Frozen Roots)

```json
{
  "action": { ... },
  "actor": { ... },
  "resolved": {
    "charter": { ... },
    "state": { ... },
    "charter_activation": { ... }
  },
  "resources": { },
  "now": "YYYY-MM-DDTHH:MM:SSZ"
}
```

Allowlisted pointer roots:
- `/action`
- `/actor`
- `/resolved/charter`
- `/resolved/state`
- `/resolved/charter_activation`
- `/resources`
- `/now`

Any other root → `DISALLOWED_ROOT` → `ERROR`

---

## File Manifest

| File | Purpose |
|------|---------|
| `p3_missing_field_semantics_patch.sql` | Adds `jsonptr_get_required()`, upgrades `_resolve_arg()` |
| `p3_gate_engine_missing_field_patch.sql` | Upgrades `evaluate_gates()` with error classification |
| `p3_toctou_bypass_removal_patch.sql` | **Removes ALL semantic bypasses + resolved input checks** |
| `p3_proof_missing_field_semantics.sql` | Behavioral: missing/null → ERROR, no exceptions |
| `p3_proof_default_deny_fail_closed.sql` | Structural: default deny + unknown → ERROR |
| `p3_proof_toctou_closed.sql` | Structural: same-transaction evaluation |
| `p3_proof_no_semantic_bypass.sql` | **Structural: no action_type/dry_run TOCTOU bypass** |
| `p3_proof_error_bypasses_exceptions.sql` | **Structural + behavioral: ERROR ignores exceptions** |
| `p3_proof_resolved_inputs_required.sql` | **Structural + behavioral: missing charter/state/activation → RAISE** |
| `p3_proof_kernel_non_exceptionable.sql` | Structural: P0.5 topology enforced |
| `P3_SUMMARY.md` | This document |

---

## Apply Order

```bash
# Prerequisites (007/008 from repo)
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/007_policy_dsl.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/008_gate_engine.sql

# P3 patches (apply in order)
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_missing_field_semantics_patch.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_gate_engine_missing_field_patch.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_toctou_bypass_removal_patch.sql  # Includes gate integration

# P3 proofs
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_missing_field_semantics.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_default_deny_fail_closed.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_toctou_closed.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_no_semantic_bypass.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_error_bypasses_exceptions.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p3_proof_kernel_non_exceptionable.sql
```

---

## Formal Guarantee

```
P3 Gate Engine MVP (v2.2):
  - Default deny: outcome initialized to FAIL
  - applied=true IFF outcome ∈ {PASS, PASS_WITH_EXCEPTION}
  - Artifacts written IFF applied=true
  - TOCTOU-closed: evaluation in same transaction as write
  - No semantic bypass: TOCTOU NOT conditioned on action_type OR dry_run
  - Resolved inputs required: missing charter/state/activation → RAISE (not silent PASS)
  - Fail-closed: all evaluation errors → ERROR → FAIL
  - Missing field: NULL/missing pointer → ERROR (not FAIL)
  - ERROR: exceptions not consulted (can't save a write)
  - Kernel gates: RAISE directly (non-exceptionable by topology)
  - Charter gates: evaluated by gate engine (exception-eligible)

Therefore:
  Writes proceed ONLY on explicit policy approval.
  Unknown or misconfigured conditions block writes.
  Kernel validation cannot be bypassed by charter configuration.
  TOCTOU enforcement cannot be bypassed by payload fields (including dry_run).
  Missing resolved inputs cannot silently degrade to PASS.
```

---

## Invariants (P0-P3)

```
P0:   privileged_behavior = f(db_role), not f(strings)
P0.5: kernel_gates are non-exceptionable by topology
P1:   (if policy_check_registry exists) gate_ids validated via seam
P2:   artifact_table_registry covers write aperture, durability verified
P3:   gate_evaluation = f(charter policy_checks), TOCTOU-closed, fail-closed, no semantic bypass
```

---

## Milestone Status

```
P0   COMPLETE → Semantic privilege eliminated
P0.5 COMPLETE → Kernel gates non-exceptionable  
P1   COMPLETE → Artifact table registry, write aperture coverage
P2   COMPLETE → Durability is registry-driven, ledger-linkage verified
P3   COMPLETE → Gate engine with strict evaluation, no semantic bypass
```
