# CPO P5 — Drift Detection Events (v3)

**Goal:** SYSTEM actor emits drift_event artifacts through `cpo.commit_action()` when
conditions indicate governance degradation. Emission is subject to the same gates,
fail-closed, and fully audited.

## Drift Signals (ALL PROVEN)

| Signal | Trigger | Test |
|--------|---------|------|
| REPEATED_EXCEPTIONS | Same gate bypassed ≥ N times in window | TEST 1 |
| EXPIRED_ASSUMPTION_REFERENCE | Decision references expired assumption | TEST 5 |
| MODE_THRASH | ≥ N mode transitions in window | TEST 6 |
| STATE_STALENESS | State snapshot age > max_age | TEST 7 |

## Invariants Enforced

- **INV-501:** Drift events are artifacts, not logs (via commit_action)
- **INV-502:** SYSTEM actor is not privileged (gates apply) — TEST 4
- **INV-503:** Deterministic triggering from canonical state
- **INV-504:** No duplicate spam (dedupe by signal/window) — TEST 2
- **INV-505:** Emission is TOCTOU-safe (expected refs required)

## Self-Test Coverage (v3)

| Test | What It Proves |
|------|----------------|
| TEST 1 | REPEATED_EXCEPTIONS at threshold (3 bypasses) |
| TEST 2 | INV-504 dedupe (re-emission skipped) |
| TEST 3 | Below threshold (2 bypasses) → no emission |
| TEST 4 | INV-502 SYSTEM blocked by gates → no artifacts |
| TEST 5 | EXPIRED_ASSUMPTION_REFERENCE triggers drift_event |
| TEST 6 | MODE_THRASH triggers drift_event (3 transitions) |
| TEST 7 | STATE_STALENESS triggers drift_event (age > max) |

## v1 → v2 Change

Added TEST 5-7 to prove all four drift signals, not just REPEATED_EXCEPTIONS.

## v2 → v3 Change

- **UTC-stable dedupe keys:** hourly window buckets use `p_now AT TIME ZONE 'UTC'` so dedupe keys are not session-timezone dependent.
- **Concurrency-safe dedupe under the write aperture lock:** drift emission acquires the same per-agent advisory lock used by `cpo.commit_action()` before checking for existing `dedupe_key` rows, preventing cross-session duplicate drift artifacts.

## Prerequisites

- P2 Step 6 v3 applied
- P3 Steps 1-3 applied
- P4 applied

## Run Order

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/011_drift_detection.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/011_drift_detection_selftest.sql
```
