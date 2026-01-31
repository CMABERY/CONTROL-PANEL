# Integration Manual — CPO ↔ FlowVersion ↔ Adapter Binding

**Status:** Phase 1 complete — canonical envelope schemas locked (SPEC_VERSION 1.0.0, CANON_VERSION 1).

This manual defines the **contract surface, evidence flow, and invariants** for integrating the CPO Governance Kernel with the FlowVersion Conformance Toolkit and domain adapters. It exists to lock terminology, reserve canonical seams, and prevent accidental divergence before implementation begins.

---

## 1) Integration Contract Surface

### Responsibility Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE                                    │
│                                                                          │
│   CPO Governance Kernel                                                  │
│   ├── Authenticates authority (DB role, not JSON)                        │
│   ├── Evaluates gates (fail-closed)                                      │
│   ├── Enforces single write aperture (commit_action)                     │
│   └── Persists governance decisions + artifacts                          │
│                                                                          │
│   Owns: AuthContext validation, PolicyDecisionRecord generation,         │
│         approval workflows, exception expiry, change control             │
│                                                                          │
│   Does NOT own: content semantics, diff/merge, domain validation         │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │
                                      │ [Canonical Envelope]
                                      │
┌─────────────────────────────────────▼───────────────────────────────────┐
│                         EVIDENCE PLANE                                   │
│                                                                          │
│   FlowVersion Conformance Layer                                          │
│   ├── Canonicalizes content (deterministic bytes)                        │
│   ├── Hashes canonical form (SHA-256)                                    │
│   ├── Validates envelope integrity                                       │
│   └── Certifies adapter conformance                                      │
│                                                                          │
│   Owns: canonical form, content hashes, golden vector verification,      │
│         trace_id propagation rules                                       │
│                                                                          │
│   Does NOT own: governance decisions, persistence, authority             │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │
                                      │ [Domain Content]
                                      │
┌─────────────────────────────────────▼───────────────────────────────────┐
│                         EXECUTION PLANE                                  │
│                                                                          │
│   Domain Adapters (+ Vendor Adapters when applicable)                    │
│   ├── Implements domain semantics (diff/merge/validate)                  │
│   ├── Produces content in base-canonical form                            │
│   ├── Generates domain-specific evidence records                         │
│   └── Upholds adapter certification invariants                           │
│                                                                          │
│   Owns: atom definition, semantic diffs, merge conflict taxonomy,        │
│         validation issue localization                                    │
│                                                                          │
│   Does NOT own: hashing, governance, persistence, trace stitching        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Handoff Points

| Boundary | Upstream Provides | Downstream Expects |
|----------|-------------------|-------------------|
| CPO → FlowVersion | `AuthContext`, `PolicyDecisionRecord` | Canonical envelope with valid signatures |
| FlowVersion → Adapter | Validated envelope, `trace_id` | Base-canonical content, propagated trace |
| Adapter → FlowVersion | Domain content, evidence records | Content in base-canonical form |
| FlowVersion → CPO | Hashed content, integrity proof | Canonical hash for artifact storage |

---

## 2) Canonical Envelopes

**Accepted Phase 1 schema set (normative):**
- `Shared.schema.json` ($defs: IDs, hashes, BlobRef, Outcome, TraceContext)
- `TraceContext.schema.json`
- `AuthContext.schema.json`
- `PolicyDecisionRecord.schema.json`
- `ModelCallRecord.schema.json`
- `ToolCallRecord.schema.json`

> **Canonical:** Field-level schemas are defined and accepted (Phase 1). Validation is fail-closed: unknown fields are rejected.
> **Versioning:** `SPEC_VERSION = 1.0.0`, `CANON_VERSION = 1`.

### AuthContext

**Purpose:** Authenticated identity + tenant context + capability grants.

**Responsibilities:**
- Propagates through all planes unchanged
- Validated by CPO at ingress
- Referenced (not re-validated) by downstream layers
- Included in evidence records for audit

**Lifecycle:**
```
[Request Ingress] → CPO validates → AuthContext frozen
                                          ↓
                    [Entire request lifetime uses same AuthContext]
```

### PolicyDecisionRecord

**Purpose:** Deterministic output of CPO gate evaluation.

**Responsibilities:**
- Records: allow/deny, gates evaluated, exceptions applied, justification
- Immutable once generated
- Hashed and stored as evidence artifact
- Required for any state mutation

**Invariant:** No downstream execution without a PolicyDecisionRecord.

### ModelCallRecord

**Purpose:** Evidence of vendor model invocation (when AI execution is in scope).

**Responsibilities:**
- Records: model ID, prompt hash, response hash, latency, token counts
- Produced by vendor adapter
- Hashed by FlowVersion layer
- Stored as evidence artifact

**Schema note:** Provider-specific payloads are content-addressed via `BlobRef` (`sha256`, `size_bytes`, `content_type`) to prevent schema drift.

### ToolCallRecord

**Purpose:** Evidence of tool invocation through the tool firewall.

**Responsibilities:**
- Records: tool ID, input hash, output hash, permissions checked, redactions applied
- Produced by tool firewall
- Hashed by FlowVersion layer
- Stored as evidence artifact

**Schema note:** Tool-specific payloads are content-addressed via `BlobRef` (`sha256`, `size_bytes`, `content_type`) to prevent schema drift.

### trace_id + span_id

**Purpose:** Correlation identifiers for end-to-end trace stitching.

**Propagation Rules:**
```
trace_id  — assigned at request ingress, immutable for request lifetime
span_id   — assigned per operation, forms parent/child tree
```

**Invariant:** Every evidence record includes `trace_id`. Orphan records are invalid.

---

## 3) Evidence Flow

### What Becomes a Ledger Artifact

| Record Type | Persisted | Hashed | Replayable | Notes |
|-------------|-----------|--------|------------|-------|
| AuthContext | Yes | Yes | Yes | Frozen at ingress |
| PolicyDecisionRecord | Yes | Yes | Yes | Required for mutation |
| Content (domain state) | Yes | Yes | Yes | Via FlowVersion canonicalization |
| ModelCallRecord | Yes | Yes | Partial | Response may be nondeterministic |
| ToolCallRecord | Yes | Yes | Yes | Deterministic if tool is deterministic |
| Validation issues | Yes | Yes | Yes | Localized to atoms |
| Merge conflicts | Yes | Yes | Yes | With resolution if provided |

### What Is Hashed

```
[Content]                 → FlowVersion.canonicalizeContent()   → SHA-256 → content_hash
[AuthContext envelope]    → FlowVersion.canonicalizeEnvelope()  → SHA-256 → auth_context_envelope_sha256
[PolicyDecision envelope] → FlowVersion.canonicalizeEnvelope()  → SHA-256 → policy_decision_envelope_sha256
[ModelCall/ToolCall envelope] → FlowVersion.canonicalizeEnvelope() → SHA-256 → envelope_hash
```

**Invariant:** `envelope_hash = sha256( canonical_json_utf8(envelope_record) )` (RFC 8785 / JCS; UTF‑8 bytes).
**Invariant:** `envelope_hash` is the artifact identifier stored by CPO.

### What Is Replayable

**Forensic replay:** Exact inputs, exact artifacts, deterministic outcome.
- Requires: all evidence records, same adapter version, same policy version

**Constrained replay:** Same inputs, bounded nondeterminism.
- Allows: model responses to differ (they're nondeterministic)
- Requires: policy decision path to match

**Invariant replay:** Policy invariants verified without full execution.
- Verifies: "would the same policy produce the same allow/deny?"
- Does not require: model/tool re-execution

### What Is Merely Observational

| Data | Status | Rationale |
|------|--------|-----------|
| Latency metrics | Observational | Not part of correctness |
| Token counts | Observational | Informational, not enforced |
| Debug logs | Observational | Not hashed, not evidence |

Observational data may be logged but is **not part of the evidence chain**.

---

## 4) Non-Negotiable Invariants

### INV-INT-001: No Adapter Bypasses CPO

```
PROHIBITED:
  Adapter → [direct persistence]
  
REQUIRED:
  Adapter → FlowVersion → CPO.commit_action() → persistence
```

**Enforcement:** CPO is the only write aperture. Adapters cannot persist state.

### INV-INT-002: No FlowVersion Certification Without Envelope Integrity

```
PROHIBITED:
  FlowVersion.certify(content)  // content alone is insufficient
  
REQUIRED:
  FlowVersion.certify(envelope) // envelope includes AuthContext + trace_id
```

**Enforcement:** Certification requires valid envelope, not just valid content.

### INV-INT-003: No Execution Without Trace Continuity

```
PROHIBITED:
  execute(request) where trace_id is absent
  execute(request) where trace_id differs from parent
  
REQUIRED:
  execute(request) where trace_id propagates from ingress to all evidence records
```

**Enforcement:** Evidence records without `trace_id` are rejected at persistence.

### INV-INT-004: No Policy Decision Without Authenticated Context

```
PROHIBITED:
  CPO.evaluate_gates(request) where AuthContext is absent
  CPO.evaluate_gates(request) where AuthContext is unvalidated
  
REQUIRED:
  CPO.evaluate_gates(request) where AuthContext is validated at ingress
```

**Enforcement:** Gate evaluation fails closed if AuthContext is missing.

### INV-INT-005: No Evidence Without Hash Chain

```
PROHIBITED:
  store(record) where envelope_hash is absent
  store(record) where envelope_hash doesn't match computed hash
  
REQUIRED:
  store(record) where envelope_hash = hash(canonical(record))
```

**Enforcement:** CPO rejects artifacts with missing or mismatched hashes.

---

## 5) TODO Zones

> Items below are **intentionally undefined** until canonical envelope schemas exist.
> This prevents premature coupling and speculative implementation.

### Schema Definitions (Blocked)

- [x] `AuthContext` field-level schema (locked)
- [x] `PolicyDecisionRecord` field-level schema (locked)
- [x] `ModelCallRecord` field-level schema (locked)
- [x] `ToolCallRecord` field-level schema (locked)
- [ ] `RetrievalRecord` field-level schema (if RAG in scope)
- [ ] `RedactionRecord` field-level schema (if redaction in scope)
- [ ] `EgressDecision` field-level schema (if egress control in scope)

### Integration Tests (Blocked on Schemas)

- [ ] End-to-end: request → policy → content → hash → persist → replay
- [ ] Trace continuity verification across all layers
- [ ] Envelope integrity rejection (malformed envelope)
- [ ] Hash mismatch rejection (tampered content)

### Operational Wiring (Blocked on Integration Tests)

- [ ] CPO commit_action accepts envelope-based artifacts
- [ ] FlowVersion produces envelope_hash for CPO storage
- [ ] Adapter certification includes envelope propagation check
- [ ] Replay runner consumes evidence chain

### Cross-Layer Conformance (Blocked on Operational Wiring)

- [ ] Golden vectors for envelope hashing (not just content hashing)
- [ ] Policy decision replay verification
- [ ] Multi-adapter trace stitching

---

## 6) Terminology Lock

| Term | Definition | Owner |
|------|------------|-------|
| **AuthContext** | Authenticated identity + tenant + capabilities | CPO |
| **PolicyDecisionRecord** | Immutable gate evaluation output | CPO |
| **envelope** | AuthContext + content + trace_id + hashes | FlowVersion |
| **envelope_hash** | Hash of canonical envelope | FlowVersion |
| **content_hash** | Hash of canonical domain content | FlowVersion |
| **trace_id** | Request-scoped correlation identifier | Assigned at ingress, propagated everywhere |
| **span_id** | Operation-scoped identifier within trace | Assigned per operation |
| **evidence record** | Any record in the audit chain | All layers produce, CPO stores |
| **artifact** | Persisted evidence with envelope_hash | CPO |

---

## Appendix: Integration Sequence (Recommended)

```
Phase 1: Define envelope schemas (COMPLETE: SPEC_VERSION 1.0.0, CANON_VERSION 1)
         └── JSON Schema + TypeScript types
         └── Canonicalization rules
         └── Golden vectors for envelope hashing

Phase 2: Wire FlowVersion envelope layer
         └── canonicalizeEnvelope()
         └── hashEnvelope()
         └── validateEnvelope()

Phase 3: Wire CPO envelope acceptance
         └── commit_action accepts envelope_hash
         └── Artifact storage keyed by envelope_hash
         └── Rejection on hash mismatch

Phase 4: Wire adapter envelope propagation
         └── Adapter receives envelope (not raw content)
         └── Adapter returns content + evidence records
         └── trace_id propagation verified

Phase 5: Build replay infrastructure
         └── Forensic replay from evidence chain
         └── Constrained replay with policy verification
         └── Invariant replay for audit

Phase 6: Certification update
         └── Adapter certification requires envelope handling
         └── Golden vectors include envelope cases
         └── CI verifies trace continuity
```

---

**End of skeleton.** Implementation begins when Phase 1 (envelope schemas) is complete.
