# Version & Lock Declaration (LOCKED)

**SPEC_VERSION:** 1.0.0  
**CANON_VERSION:** 1  

This repository contains a canonically locked governance + evidence + replay system.

## What “v1.0.0” means (system boundary)

v1.0.0 refers to the following locked contract set:

- Envelope record types and schemas:
  - `AuthContext`, `PolicyDecisionRecord`, `ModelCallRecord`, `ToolCallRecord`, `TraceContext`
- Canonicalization and hashing:
  - RFC 8785 (JCS) canonical JSON
  - `envelope_hash := sha256(utf8(canonical_json(envelope_record)))`
- Failure taxonomy and step ordering at the CPO gate (`commit_action`)
- Cross-layer conformance suite and certification artifact format
- Replay semantics (forensic / constrained / invariant) and replay result artifact format
- Phase 6 UI posture: read-only artifact consumer + controlled expansion strictly via certification artifacts

## What requires a version bump (non-exhaustive)

Any of the following constitutes a breaking change and requires a new canon revision:

- Adding, removing, renaming, or changing semantics of any envelope field
- Changing JSON Schema constraints (including allowing unknown fields)
- Changing canonicalization rules (key ordering, number encoding, string normalization)
- Changing hashing inputs or algorithms
- Changing failure classification rules or decision order
- Changing certification criteria or revocation semantics
- Changing replay guarantees or what constitutes PASS/FAIL

## Phase 0 reset requirement

Further work beyond custodial operations requires an explicit versioned initiation phase:

- New spec/canon versions must be declared.
- New schemas and goldens must be authored.
- Integration/conformance/replay proofs must be re-established.

No silent mutation is permitted.
