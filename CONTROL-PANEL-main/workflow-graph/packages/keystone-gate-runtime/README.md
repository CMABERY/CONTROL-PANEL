# keystone-gate-runtime (LOCKED)

This package is the **contract-locked runtime + proofs bundle** for the Keystone Gate envelope system.

It contains:

- **Phase 1** canonical envelope schemas (`schemas/`) and record goldens (`goldens/*.goldens.json`)
- **Phase 2** integration tests (see `test/phase2.integration.test.js`)
- **Phase 3** operational wiring (FlowVersion envelope ops + CPO `commit_action`)
- **Phase 4** cross-layer conformance + certification artifacts
- **Phase 5** replay plumbing (see `PHASE5_REPLAY.md` and `src/replay/`)

This package is **test-oriented**. It is not production wiring.

## Run tests

From repo root:

```sh
cd workflow-graph
npm -w keystone-gate-runtime test
```

## Canonical versions

- SPEC_VERSION: **1.0.0**
- CANON_VERSION: **1**
