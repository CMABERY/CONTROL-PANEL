# Audit Readiness Checklist (Inspection-Only)

This checklist is satisfiable by inspecting repository artifacts only.

## Determinism guarantees

- [ ] Canonicalization rules are specified (RFC 8785/JCS)  
      Evidence: `docs/keystone/CANONICALIZATION_RULES.md`
- [ ] Envelope hashing is defined as SHA-256 over canonical JSON bytes  
      Evidence: `docs/keystone/CANONICALIZATION_RULES.md`, `INTEGRATION_MANUAL.md`
- [ ] Record goldens exist and bind canonical JSON → SHA-256  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/goldens/*.goldens.json`

## Evidence immutability

- [ ] Envelope artifacts are keyed by `envelope_hash` (not content-only hashes)  
      Evidence: `INTEGRATION_MANUAL.md`, `workflow-graph/packages/keystone-gate-runtime/src/cpo-kernel.js`
- [ ] Blob payloads are referenced via content-addressed BlobRef (sha256 + size + content_type)  
      Evidence: schema defs in `workflow-graph/packages/keystone-gate-runtime/schemas/Shared.schema.json`

## Gate enforcement (single write aperture)

- [ ] `commit_action` performs: schema → canonicalize → hash → compare → prereqs → trace → authorization  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/src/cpo-kernel.js`
- [ ] Fail-closed taxonomy implemented and deterministic  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/src/error-classification.js`

## Replay availability

- [ ] Forensic replay exists and is bit-exact verification  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/src/replay/forensic-replay.js`
- [ ] Constrained replay exists and scopes variance explicitly  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/src/replay/constrained-replay.js`
- [ ] Invariant replay exists and performs no execution  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/src/replay/invariant-replay.js`
- [ ] Replay result artifacts are content-addressed and stored as ledger artifacts  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/src/replay/replay-result-artifact.js`

## Certification & revocation visibility

- [ ] Certification artifact format exists and is content-addressed  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/certifications/*.cert.json`
- [ ] Revocation rules/templates are present  
      Evidence: `workflow-graph/packages/keystone-gate-runtime/certifications/*revocation*`

## UI epistemic honesty

- [ ] UI is specified as a pure reader of artifacts (no hidden state, no overrides)  
      Evidence: `docs/keystone/PHASE6_REPLAY_UI_SPEC.md`
- [ ] Verified / Inferred / Not replayable labeling rules exist  
      Evidence: `docs/keystone/PHASE6_REPLAY_UI_SPEC.md`

## Version & lock declaration

- [ ] Canonical versions and bump rules are stated  
      Evidence: `VERSION_LOCK.md`, `CANONICAL_CLOSEOUT.md`
