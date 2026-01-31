# Phase 6 — Replay UI & Controlled Expansion (LOCKED)

**Status:** Complete and canonically locked (SPEC_VERSION 1.0.0, CANON_VERSION 1)

This document specifies Phase 6 operational surfaces as **read-only artifact consumers**.

## 1) UI posture (non-negotiable)

The UI is a **pure evidence renderer**:

- Reads only content-addressed ledger artifacts.
- Maintains no hidden state (URL + fetched artifacts define state).
- Does not canonicalize, hash, or schema-validate envelopes.
- Does not mutate envelopes, certifications, revocations, or replay results.
- Does not re-run policy or execution; it may invoke replay engines only to create replay result artifacts.

## 2) Artifact types the UI may consume (closed set)

- Envelope artifacts (accepted)
- Envelope artifacts (rejected-attempt)
- Replay result artifacts
- Certification artifacts
- Revocation artifacts

Any artifact not in this set must be treated as unsupported / out-of-scope.

## 3) Epistemic honesty labels (required)

Every rendered claim MUST be labeled as exactly one of:

- **Verified** — backed by a specific artifact hash the UI links to.
- **Inferred** — derived from artifacts (aggregation / counting), explicitly marked.
- **Not replayable** — required evidence or replay result artifact absent.

No “success” indicators are permitted without a backing replay result artifact.

## 4) Navigation keys (deterministic)

Primary keys:

- `trace_id`
- `envelope_hash` / `artifact_sha256`
- certification record (`adapter_id`, `certified_version`)

Trace ordering MUST match replay resolver ordering:

AuthContext → PolicyDecisionRecord → Evidence (ModelCallRecord/ToolCallRecord), then time key, then hash.

Rejected-attempt artifacts must never be hidden.

## 5) Controlled expansion (mechanical only)

The only permitted onboarding path for a new adapter/tool/vendor-backed path:

1) Submit evidence through the same CPO gate.
2) Run conformance suite.
3) Emit certification artifact (content-addressed).
4) UI surfaces “Available” only if certified and not revoked.

Revocation artifacts take effect immediately and must be visible.

## 6) Security & provenance display

Hashes, versions, and producer.layer are first-class fields and must be visible on all relevant screens.
Missing artifacts must be rendered as missing evidence, not smoothed over.

This document is descriptive of locked behavior. Any change requires a new canon revision.
