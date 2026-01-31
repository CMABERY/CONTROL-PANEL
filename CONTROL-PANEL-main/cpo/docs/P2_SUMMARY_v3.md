# P2 COMPLETE: Registry-Driven Durability

## Summary

P2 delivers registry-driven durability where export, rehydrate, and verification all iterate the artifact table registry—no hand-curated lists survive.

## Audit Response: v2 → v3 → v3.1 → v3.2 → Wiring

### v2 → v3 (Schema + Projection Fixes)

| Issue | v2 Problem | v3 Fix |
|-------|------------|--------|
| **Column names wrong** | Used `id`, `version`, `snapshot` | Uses actual: `action_log_id`, `charter_version_id`, `seq`, etc. |
| **Non-existent columns** | Referenced `content_hash`, `snapshot_hash` | Removed; hash computed at export time |
| **Projections not modeled** | No policy for `cpo_agent_heads` | Added `table_kind = 'projection'` with `is_canonical=false` |
| **Proof fail-open** | Zero extracted targets → WARN → PASS | Zero targets → HARD FAIL |

### v3 → v3.1 (Mechanical Blockers Fixed)

| Blocker | v3 Problem | v3.1 Fix |
|---------|------------|----------|
| **A: Seed INSERTs** | Positional VALUES (fails on fresh table) | Explicit column lists in all INSERTs |
| **B: Overload ambiguity** | `ORDER BY pronargs DESC LIMIT 1` guessing | Exact `regprocedure` signature: `cpo.commit_action(text, jsonb, jsonb, uuid, uuid)` |

### v3.1 → v3.2 (Registry Truthfulness)

| Issue | v3.1 Problem | v3.2 Fix |
|-------|--------------|----------|
| **Non-existent logical_id columns** | `assumption_event_id`, `exception_event_id`, `drift_resolution_id`, `change_id` don't exist in repo v2.2 | Changed to `id` (bigserial) for these 4 tables |
| **No column existence proof** | Registry could lie about columns | Added PROOF 6: verifies all declared columns exist on tables |

---

## v3.2 File Manifest

| File | Purpose |
|------|---------|
| `p2_artifact_table_registry_v3.sql` | **Truthful registry with ACTUAL column names** |
| `p2_proof_write_aperture_coverage_v3.sql` | **7 proofs including column existence verification** |
| `p2_durability_drill_wiring.sql` | **Registry-driven export/rehydrate/verify functions** |
| `p2_proof_durability_wiring.sql` | **Structural proof that durability goes through registry seam** |
| `P2_SUMMARY_v3.md` | This document |

---

## Durability Drill Wiring (NEW)

### Upgraded Functions

| Function | What It Does | Registry Usage |
|----------|--------------|----------------|
| `export_evidence_pack(uuid)` | Exports all canonical artifacts for agent | Iterates `get_canonical_artifact_types()` |
| `rehydrate_agent(jsonb, text)` | Rebuilds agent from pack into target schema | Uses `insert_*` columns from registry |
| `verify_reconstruction(uuid, text, text)` | Verifies equivalence between schemas | Hash multiset per registry artifact type |
| `verify_heads_equivalence(uuid, text, text)` | Checks heads projection match | Utility for projection verification |
| `durability_round_trip_test(uuid)` | Full export→rehydrate→verify cycle | Wires all three core functions |

### Equivalence Method

**NOT just row counts.** Strong equivalence means:

```
∀ artifact_type ∈ registry:
  source_hashes = sorted(sha256(content) for each row in source)
  target_hashes = sorted(sha256(content) for each row in target)
  assert source_hashes = target_hashes
```

This catches:
- Missing rows (different count)
- Modified content (different hash)
- Extra rows (different multiset)

### Generated Column Handling

Rehydrate inserts using ONLY insertable columns:
```sql
INSERT INTO target.cpo_action_logs (
  agent_id,           -- insert_agent_id_column
  content             -- insert_content_column
) VALUES ($1, $2);
-- action_log_id and seq are GENERATED, recompute automatically
```

---

## Column Name Corrections (from 000_bootstrap.sql v2.2)

### Tables with GENERATED UUID columns

| Table | Generated ID Column | Generated Seq Column |
|-------|---------------------|----------------------|
| `cpo_action_logs` | `action_log_id` | `seq` |
| `cpo_charters` | `charter_version_id` | — |
| `cpo_charter_activations` | `activation_id` | `seq` |
| `cpo_state_snapshots` | `state_snapshot_id` | `seq` |
| `cpo_decisions` | `decision_id` | — |
| `cpo_assumptions` | `assumption_id` | — |
| `cpo_exceptions` | `exception_id` | — |
| `cpo_drift_events` | `drift_event_id` | — |

### Tables with bigserial `id` (no generated UUID)

| Table | ID Column | Notes |
|-------|-----------|-------|
| `cpo_assumption_events` | `id` (bigserial) | No `assumption_event_id` column |
| `cpo_exception_events` | `id` (bigserial) | No `exception_event_id` column |
| `cpo_drift_resolutions` | `id` (bigserial) | No `drift_resolution_id` column |
| `cpo_changes` | `id` (bigserial) | `change_id` lives inside `content` jsonb |

**Equivalence strategy for bigserial tables:** Do NOT rely on `id` matching across worlds. Use content-hash multiset comparison instead.

### Projections (NOT exported)

| Table | Classification |
|-------|----------------|
| `cpo_agent_heads` | `table_kind = 'projection'`, `is_canonical = false`, `is_exported = false` |

---

## Proof Hardening (v3 Changes)

### 1. Explicit Overload Resolution

```sql
-- v2 (vulnerable): silent "pick one"
SELECT p.oid ... ORDER BY pronargs DESC LIMIT 1

-- v3 (hardened): report all overloads, explain selection
SELECT COUNT(*), string_agg(...) INTO v_candidate_count, v_signature
IF v_candidate_count > 1 THEN
  RAISE NOTICE 'Multiple overloads found...';
END IF;
```

### 2. Hard-Fail on Zero Targets

```sql
-- v2 (fail-open): warn and continue
IF v_all_tables IS NULL THEN
  RAISE NOTICE 'WARNING: No targets found';
END IF;

-- v3 (fail-closed): exception
IF array_length(v_all_tables, 1) IS NULL THEN
  RAISE EXCEPTION 'PROOF FAIL: Extracted ZERO INSERT targets';
END IF;
```

### 3. Baseline Target Assertion

```sql
-- v3: spine MUST be present
IF NOT 'cpo_action_logs' = ANY(v_all_tables) THEN
  RAISE EXCEPTION 'PROOF FAIL: Baseline target cpo_action_logs NOT found';
END IF;
```

### 4. Exact regclass Matching

```sql
-- v2 (vulnerable): substring matching
WHERE table_regclass::text LIKE '%' || v_tbl

-- v3 (exact): regclass equality
v_registered := ('cpo.' || v_tbl)::regclass;
WHERE r.table_regclass = v_registered
```

---

## Architecture: Canonical vs Projection

### Write Aperture Coverage Theorem

```
∀ table T: commit_action() can INSERT INTO T
  → T ∈ artifact_table_registry

∀ table T: T.table_kind = 'canonical'
  → T.is_exported = true ∧ T.export_order IS NOT NULL

∀ table T: T.table_kind = 'projection'
  → T.is_exported = false (rebuilt, not exported)
```

### Export Completeness

```
Export iterates: get_canonical_artifact_types()
  → returns WHERE table_kind='canonical' AND is_exported=true

Registry covers: all commit_action INSERT targets

Therefore: Export covers all possible canonical artifacts
```

### Rehydrate Equivalence

Projections are NOT in the export, but are **rebuildable**:

1. Import canonical artifacts
2. Call rebuild functions (e.g., `cpo.rebuild_agent_heads()`)
3. Verify heads match expected

---

## P2 v3.2 Proof Summary

| Proof | Method | What It Proves |
|-------|--------|----------------|
| **1** | Exact `regprocedure` | commit_action resolved by canonical signature |
| **2** | Extraction + hard-fail | INSERT targets non-empty |
| **3** | Baseline assertion | cpo_action_logs is target |
| **4** | Exact regclass match | All targets registered |
| **5** | Canonical → exported | No orphan canonical tables |
| **6** | `pg_attribute` check | All declared columns exist on tables |
| **7** | Function body inspection | Dual-condition immutability guard |

---

## Durability Wiring Proofs

| Proof | Method | What It Proves |
|-------|--------|----------------|
| **1** | Function body inspection | export_evidence_pack iterates registry |
| **2** | Function body inspection | rehydrate_agent uses registry + insert columns |
| **3** | Function body inspection | verify_reconstruction uses registry + hash comparison |
| **4** | Pattern scan | No orphan durability functions bypass registry |
| **5** | Existence check | Registry helper functions exist and return data |
| **6** | Wiring check | Round-trip test wires all three functions |

---

## P2 Completion Checklist

| Requirement | Status |
|-------------|--------|
| Registry covers all write-aperture targets | ✅ Write aperture coverage proof |
| Registry columns are truthful | ✅ Column existence proof (PROOF 6) |
| Export iterates registry | ✅ `export_evidence_pack()` calls `get_canonical_artifact_types()` |
| Rehydrate uses insert columns | ✅ `rehydrate_agent()` uses registry insert columns |
| Equivalence is hash-based | ✅ `verify_reconstruction()` uses SHA256 multiset |
| Round-trip test exists | ✅ `durability_round_trip_test()` |
| Structural wiring proof | ✅ `p2_proof_durability_wiring.sql` |

---

## Usage

### Export Agent

```sql
SELECT cpo.export_evidence_pack('agent-uuid-here');
-- Returns JSONB pack with all canonical artifacts
```

### Rehydrate Agent

```sql
SELECT cpo.rehydrate_agent(pack_jsonb, 'target_schema');
-- Rebuilds agent into target schema
```

### Verify Equivalence

```sql
SELECT cpo.verify_reconstruction('agent-uuid', 'cpo', 'target_schema');
-- Returns JSONB with per-artifact-type hash comparison
```

### Full Round-Trip Test

```sql
SELECT cpo.durability_round_trip_test('agent-uuid');
-- Export → Rehydrate → Verify → Cleanup
-- Returns pass/fail with details
```

---

## Invariants (All Phases Complete)

```
P0:   privileged_behavior = f(db_role), not f(strings)
P0.5: kernel_gates are non-exceptionable by topology
P1:   gate_definitions = f(registry), resolved via seam on enforcement path
P2:   durability = f(registry), anchored to write aperture, hash-verified
```

---

## Milestone Status

```
P0   COMPLETE → Semantic privilege eliminated
P0.5 COMPLETE → Kernel gates non-exceptionable  
P1   COMPLETE → Gate definitions are data, registry-resolved
P2   COMPLETE (v3.2 + wiring)
     ✅ Registry seed matches actual schema
     ✅ Projections modeled as non-canonical
     ✅ Write aperture proof is fail-closed
     ✅ Exact regprocedure signature (no LIMIT 1 guessing)
     ✅ Explicit column lists (works on fresh table creation)
     ✅ All logical_id columns exist (bigserial 'id' for 4 tables)
     ✅ PROOF 6: Column existence verification
     ✅ export_evidence_pack() iterates registry
     ✅ rehydrate_agent() uses insert columns
     ✅ verify_reconstruction() uses hash multiset
     ✅ Structural wiring proof
```

## P2 Formal Guarantee

```
Durability is registry-driven:
  - Every write-aperture target is registered
  - Registry is truthful (columns exist)
  - Export iterates registry (no hand list)
  - Rehydrate uses insert columns (generated IDs recompute)
  - Equivalence is hash-based (not count-based)

Therefore:
  The world can be rebuilt from the ledger alone,
  without believing in anyone's memory.
```
     ✅ Exact regclass matching
     → Durability drill upgrade pending
```
