# P6 — Change Control as Kernel Physics (v3)

P6 makes charter mutation a *kernel-mandatory* check: the constitution can’t amend itself by deleting the amendment rule.

This v3 package upgrades **change-control evaluation** to eliminate semantic privilege (no `SYSTEM_%`/`BOOTSTRAP_%` string logic), enforce deterministic approvals with knife-edge expiry semantics, and block replay.

## Locked invariants

| ID | Invariant |
|---:|-----------|
| INV-601 | Charter mutation requires a change package artifact (`changes[]`) |
| INV-602 | Change package must include deterministic approvals; approval expiry enforced (knife-edge: `expiry_at <= now` is expired) |
| INV-603 | Malformed/unknown/partial change package ⇒ **FAIL** (`applied=false`) |
| INV-604 | Charter activation/mutation is TOCTOU-safe (expected refs, same snapshot) — enforced by `commit_action` Stage 3 |
| INV-605 | Replay blocked (unique `change_id` and/or `dedupe_key`) |
| INV-606 | Bootstrap exemption only for authenticated genesis bootstrap (`is_genesis` + DB-role-derived capability), never via strings |

## What changes in v3

### 1) No semantic bypasses
* **Removed** `p_action_type LIKE 'BOOTSTRAP_%'` and `LIKE 'SYSTEM_%'` paths.
* **Genesis exemption** is allowed **only** when:

```
(is_genesis = true) AND (capability = 'KERNEL_BOOTSTRAP')
```

No JSON field, action_type prefix, or caller-supplied string can grant exemption.

### 2) Approvals are deterministic + time-bounded
Each approval **must** include `expiry_at` and it is enforced with a knife-edge inclusive rule:

* `expiry_at <= now` ⇒ expired ⇒ **FAIL**
* `expiry_at IS NULL` / missing / unparsable ⇒ invalid ⇒ **FAIL**
* duplicate approver IDs ⇒ **FAIL** (determinism)

### 3) Replay protection
P6 blocks replay via a **gate check** plus **physical indexes**:

* Gate check: fails if an existing `cpo.cpo_changes` row already contains the same `change_id` or `dedupe_key`.
* Unique indexes (partial expression indexes) prevent accidental reintroduction.

If legacy duplicates exist, index creation will fail—intentionally surfacing an integrity problem.

## Change package contract

P6 expects a charter-mutation commit to carry `artifacts.changes[]` with a *change package* object shaped like:

```json
{
  "change_id": "<uuid>",
  "change_type": "CHARTER_AMENDMENT" | "CHARTER_ACTIVATION",
  "dedupe_key": "<string, optional>",
  "targets": {
    "charter_version_ids": ["<uuid>", ...],
    "charter_activation_ids": ["<uuid>", ...]
  },
  "approvals": [
    {
      "approved_by": {"id": "<string>"},
      "approved_at": "<timestamptz>",
      "expiry_at": "<timestamptz>"
    }
  ]
}
```

The `targets` must cover every proposed charter version and activation in the same commit.

## Files

| File | Purpose |
|------|---------|
| `p6_change_control_kernel_patch.sql` | Runtime patch: new 8-arg kernel function + 6-arg wrapper, replay indexes |
| `p6_change_control_proofs.sql` | Behavioral proofs for INV-601..INV-606 |
| `p6_ci_guard_change_control.sql` | Structural CI guard: bans semantic bypass patterns; ensures write aperture wiring |
| `deploy_p6.sh` | Strict deployment runner |

## Apply order

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p6_change_control_kernel_patch.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p6_change_control_proofs.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f p6_ci_guard_change_control.sql
```

## Notes on integration

The CI guard intentionally fails if it cannot find a call chain from:

```
commit_action() → … → evaluate_change_control_kernel()
```

It accepts either:

* a direct call in `commit_action`, or
* an indirect call via `evaluate_kernel_mandatory_gates`.

If your repo uses a differently named prelude function, update the guard accordingly.
