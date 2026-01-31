# Phase 5 — Replay Plumbing (Evidence-Locked)

This package implements replay as deterministic verification over **persisted ledger artifacts**
produced by the Phase 3 CPO gate.

Replay is **not** policy authoring, not UI, not vendor execution. It is mechanical verification.

## Canonical implementations (source paths)

- Replay index + resolver: `src/replay/replay-index.js`
- Replay engines:
  - Forensic: `src/replay/forensic-replay.js`
  - Constrained: `src/replay/constrained-replay.js`
  - Invariant: `src/replay/invariant-replay.js`
- Replay result artifacts: `src/replay/replay-result-artifact.js`

Note: legacy convenience wrappers exist under `src/replay-*.js` and `src/replay-index.js`.
They are **not** the canonical implementations and are retained only as historical/compatibility files.

## Determinism guarantees

- Envelope canonicalization: RFC 8785 / JCS
- Envelope identity: `envelope_hash := sha256(utf8(canonical_json(envelope)))`
- Replay result identity: `replay_result_sha256 := sha256(utf8(canonical_json(result)))`

Replay result records include `generated_at` as an ISO-8601 timestamp string.
Replay tests provide a fixed clock value to preserve determinism; otherwise a default epoch value
is used by engines when no clock is provided.

## Replay modes

### Forensic replay

Bit-exact verification:

1. Re-validate schema for each accepted envelope.
2. Re-canonicalize and assert exact match to stored canonical bytes.
3. Re-hash and assert exact match to stored `envelope_hash`.
4. Re-run prerequisite resolution, trace continuity, and authorization checks over the resolved chain.

Optional: include rejected-attempt artifacts in the resolved chain view (they remain evidence; replay does not
reinterpret their original classification).

### Invariant replay

No execution. Verifies:

- schema validity
- hash integrity
- prerequisite existence
- trace continuity
- authorization correctness (`decision.result == "allow"` for evidence)

### Constrained replay

Compares two traces already persisted in the ledger:

- both traces must pass invariant replay
- policy-path equivalence must hold (policy/request/decision normalized)
- hash drift allowed only for explicitly scoped variance (e.g., response BlobRef) as configured by replay policy
- allowed differences are enumerated explicitly in diagnostics

## Replay failure classes

Replay reuses Phase 2/3 failure classes when applicable:

- `SCHEMA_REJECT`
- `HASH_MISMATCH`
- `MISSING_PREREQ`
- `TRACE_VIOLATION`
- `UNAUTHORIZED_EXECUTION`

Replay-specific classes (derived, deterministic):

- `REPLAY_CHAIN_NOT_FOUND`
- `REPLAY_POLICY_PATH_MISMATCH`
- `REPLAY_VARIANCE_VIOLATION`
