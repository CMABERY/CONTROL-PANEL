# Canonical Closeout — Keystone Gate System (LOCKED)

**Closeout timestamp (UTC):** 2026-01-31T00:00:00Z  
**SPEC_VERSION:** 1.0.0  
**CANON_VERSION:** 1  

This file is an authoritative progress compilation for the Keystone Gate envelope system
(Phases 1–6). It is a **record of completion**, not a plan.

## Phase completion ledger

- **Phase 1 — Canonical Envelope Schemas:** COMPLETE (LOCKED)
  - Draft 2020-12 schemas: `workflow-graph/packages/keystone-gate-runtime/schemas/`
  - TypeScript structural types: `workflow-graph/packages/keystone-gate-runtime/types.ts`
  - Record goldens: `workflow-graph/packages/keystone-gate-runtime/goldens/*.goldens.json`
  - Canonicalization rules: `docs/keystone/CANONICALIZATION_RULES.md`

- **Phase 2 — Integration Tests:** COMPLETE (LOCKED)
  - Test suite: `workflow-graph/packages/keystone-gate-runtime/test/phase2.integration.test.js`
  - End-to-end goldens: `workflow-graph/packages/keystone-gate-runtime/goldens/integration.e2e.goldens.json`

- **Phase 3 — Operational Wiring:** COMPLETE (LOCKED)
  - FlowVersion envelope ops: `workflow-graph/packages/keystone-gate-runtime/src/flowversion-envelope.js`
  - CPO gate boundary: `workflow-graph/packages/keystone-gate-runtime/src/cpo-kernel.js`
  - Failure taxonomy implementation: `workflow-graph/packages/keystone-gate-runtime/src/error-classification.js`

- **Phase 4 — Cross-Layer Conformance:** COMPLETE (LOCKED)
  - Conformance suite test: `workflow-graph/packages/keystone-gate-runtime/test/phase4.conformance.test.js`
  - Conformance goldens: `workflow-graph/packages/keystone-gate-runtime/goldens/conformance*.goldens.json`
  - Certification artifacts: `workflow-graph/packages/keystone-gate-runtime/certifications/`

- **Phase 5 — Replay Plumbing:** COMPLETE (LOCKED)
  - Replay engines: `workflow-graph/packages/keystone-gate-runtime/src/replay/`
  - Replay suite test: `workflow-graph/packages/keystone-gate-runtime/test/phase5.replay.test.js`
  - Replay docs: `workflow-graph/packages/keystone-gate-runtime/PHASE5_REPLAY.md`

- **Phase 6 — Replay UI & Controlled Expansion:** COMPLETE (LOCKED)
  - UI/ops specification: `docs/keystone/PHASE6_REPLAY_UI_SPEC.md`

## Certified adapters/tools (Phase 4)

- **adapter.http** — certified (`certified_version`: `1.0.0-test`)
  - Certification bundle: `workflow-graph/packages/keystone-gate-runtime/certifications/adapter.http__1.0.0-test.cert.json`

No other adapters/tools are certified in this repository bundle.

## Replay modes available (Phase 5)

- Forensic replay (bit-exact)
- Constrained replay (policy-path equivalence; scoped variance)
- Invariant replay (no execution)

Replay produces content-addressed replay result artifacts stored as generic ledger artifacts.

## Canonical version boundary (v1.0.0)

In this repository bundle:

- Envelope record schemas, canonicalization rules, hash semantics, failure taxonomy, conformance criteria,
  and replay semantics are **LOCKED** at SPEC_VERSION 1.0.0 / CANON_VERSION 1.
- Any change to any of the above requires a **new canon revision** (Phase 0 reset) and re-proof of invariants.

## Authority file hashes (SHA-256 over file bytes)

Hashes are provided for audit pinning of the primary authority surfaces.

- `.github/workflows/ci.yml`: `c28cb8e57fde03deaeb04d8907b7e65a3e92aa446e6cb9fdd024e18902ce0525`
- `AUDIT_READINESS_CHECKLIST.md`: `0597845e781367c949297ac04506433fb53c8278c92392d8f3b4a9f05470d78e`
- `CANONICAL_CLOSEOUT.md`: `40f4b8eebb619242333e23f09df057571c3fe79b01f406d6f5c891abdbbaf111`
- `INTEGRATION_MANUAL.md`: `73b01fc61e1058a61989c9806100be028e4bfec3d0ba20441804a573581ac64a`
- `VERSION_LOCK.md`: `848f6fcb523da09c5e8c09547fab8659203105f2f9aeba02f0347f460e704021`
- `cpo/STATUS.json`: `69ff605e31b1764edb3e04eab9c0c6c2d0c7e9b316aaaaaee573e14cf68aacf8`
- `docs/keystone/CANONICALIZATION_RULES.md`: `5874f8a03c15f9121f37fac54606a7c42d7df22c979203268c16c830773091a8`
- `docs/keystone/PHASE6_REPLAY_UI_SPEC.md`: `98743f2b9b0579e83c78467c47d8c2bef0b666d895b020c9be9718028b551c06`
- `workflow-graph/packages/flowversion-conformance/bundle.schema.json`: `0f302f88b213db7a39dfa58d546a538a65425ee208aa303bd8fa33ddc4be48bb`
- `workflow-graph/packages/flowversion-conformance/goldens.json`: `0f799dc0920cb0844eceb9cdc2e914236c40706955ed8e0e94123e7625dcb7b1`
- `workflow-graph/packages/keystone-gate-runtime/certifications/adapter.http__1.0.0-test.cert.json`: `68a77e6f1c41eafda9e92f317b932f87c36d165a42a986c442938823ec9c129c`
- `workflow-graph/packages/keystone-gate-runtime/goldens/AuthContext.goldens.json`: `964cdda5aa925f9d627e6bcdc5ed3554e37b1b000c4014790d693e87f0386351`
- `workflow-graph/packages/keystone-gate-runtime/goldens/ModelCallRecord.goldens.json`: `d169f9a150f4476e9877123a99dfdb96edc3238245bfcca03f4c2a8731aea156`
- `workflow-graph/packages/keystone-gate-runtime/goldens/PolicyDecisionRecord.goldens.json`: `77e977f84f5cc37a571fc702d85f2256d74e8d56e1ac1cf0e4a97e6cf9b5a9a3`
- `workflow-graph/packages/keystone-gate-runtime/goldens/ToolCallRecord.goldens.json`: `a75176c5fbe4cf63f82ecd50037d65e828f11368237bd09553e3958d356dc325`
- `workflow-graph/packages/keystone-gate-runtime/goldens/TraceContext.goldens.json`: `62de29d9909207e6afdc0211f8ea2872d13ce7a83fe7292a856ba03d5d6f6321`
- `workflow-graph/packages/keystone-gate-runtime/goldens/conformance.multi_producer.goldens.json`: `d2f65facb4b4d94ec8d76080dd0aea34bdbea166713f6357d535505e86e4abb8`
- `workflow-graph/packages/keystone-gate-runtime/goldens/integration.e2e.goldens.json`: `bdc366faa5868f324e27cb6c2e42e3402b2e1422a0e3ec633cf8a980f06ad03f`
- `workflow-graph/packages/keystone-gate-runtime/schemas/AuthContext.schema.json`: `862c106d97ae22b6786936b65c4a610363239b72e4976bc4e27dd7dbeec51d29`
- `workflow-graph/packages/keystone-gate-runtime/schemas/ModelCallRecord.schema.json`: `69fffa79f00b11d49802e43098e6115dc27adeb48b7c027182eecc79d3e5853c`
- `workflow-graph/packages/keystone-gate-runtime/schemas/PolicyDecisionRecord.schema.json`: `7a8f062e37d84b742ad3b2e6ca7586f0499b7a3454a5ae287f4b7ec48367f4cf`
- `workflow-graph/packages/keystone-gate-runtime/schemas/Shared.schema.json`: `3d0a93e68ddeb5e4bd43623c2022aeced078d22e4caeef02a5b8da99846c0692`
- `workflow-graph/packages/keystone-gate-runtime/schemas/ToolCallRecord.schema.json`: `41c82227a72cd5fbc938c5b5ad21d8a812a629740db122c75e2a2fb5f8d921f2`
- `workflow-graph/packages/keystone-gate-runtime/schemas/TraceContext.schema.json`: `e27986fb730e6c1576cbff491c1c1c3420b4479ea3df77278c61d089fafaae46`

