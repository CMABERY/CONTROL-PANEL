# Governance

Unified governance and version control repository implementing **governance through physics, not policy**.

**Repository status:** COMPLETE and canonically locked.

This repository is a **static proof bundle**:
- Contracts are locked (closed-world).
- Evidence is content-addressed and replayable.
- No residual design surface remains without an explicit, versioned canon revision.

Canonical closeout: `CANONICAL_CLOSEOUT.md`  
Keystone integration contract: `INTEGRATION_MANUAL.md`

## Projects

### CPO Governance Kernel (`/cpo`)

A PostgreSQL-native governance kernel where:
- All state mutations flow through a **single write aperture** (`cpo.commit_action`)
- Enforcement is **fail-closed by default**
- Governance is **physics, not policy**—rules cannot disable themselves
- Every invariant is **proven via deterministic self-tests**

**Operational Mantra:**
```
Authority is authenticated.
Physics outranks policy.
Enumerations are structural.
Evaluation is closed-world.
Exceptions are expiring authority.
Drift becomes ledger artifacts.
Change control governs the rules.
Every commit re-proves the world.
```

**Phase Status:** See `cpo/STATUS.json` for canonical status authority.

| Phase | Name | Status |
|-------|------|--------|
| P1 | Policy Check Registry | ✅ Complete |
| P2 | Persistence / Write Aperture | ✅ Complete |
| P3 | Gate Integration / TOCTOU | ✅ Complete |
| P4 | Exception Expiry | ✅ Complete |
| P5 | Drift Detection | ✅ Complete |
| P6 | Change Control | ✅ Complete (v3.1) |
| P7 | Release Closure Pipeline | ✅ Complete |

### FlowVersion Conformance Toolkit (`/workflow-graph/packages/flowversion-conformance`)

A domain-native version control kit that:
- Generalizes Git's trust properties beyond files/lines
- Enforces correctness via **kernel/adapter contract + conformance harness**
- Provides certification-grade validation with schema, canonicalization, and golden vectors

**Key Components:**
- JSON Schema validation (Draft 2020-12)
- Deterministic canonicalization (integer-only for portability)
- Golden vectors with SHA-256 hashes
- CLI: `npx flowversion-conformance test`


### Keystone Gate Envelope System (`/workflow-graph/packages/keystone-gate-runtime`)

A contract-locked envelope + governance + replay system spanning:

- **Phase 1** canonical envelope schemas + goldens (Draft 2020-12, RFC 8785/JCS)
- **Phase 2** integration tests and failure taxonomy
- **Phase 3** operational wiring (FlowVersion envelope ops + CPO `commit_action`)
- **Phase 4** cross-layer conformance + adapter certification
- **Phase 5** replay plumbing (forensic / constrained / invariant)
- **Phase 6** replay UI & controlled expansion specification (artifact-only)

**Canonical docs:**
- `INTEGRATION_MANUAL.md`
- `docs/keystone/CANONICALIZATION_RULES.md`
- `docs/keystone/PHASE6_REPLAY_UI_SPEC.md`

**Run tests:**
```bash
cd workflow-graph
npm -w keystone-gate-runtime test
```

### Workflow Graph Reference (`/workflow-graph/packages/workflow-graph-adapter`)

A reference domain implementation demonstrating the full FlowVersion vertical slice:
- Workflow graph adapter with `canonicalizeDomain`, `diff`, `merge`, `validate`
- Domain-specific goldens and fixtures
- Five-questions specification

## Integration Model

These projects use **modular connection** (not merge, not independence):

```
[Domain Content]
    → FlowVersion: canonicalize → validate → hash
    → CPO: commit_action (content as artifact payload)
    → CPO: gate evaluation (governance)
    → CPO: persist (action_log + artifacts)
```

FlowVersion provides content integrity; CPO provides governance enforcement.

## Running the CPO Pipeline

```bash
cd cpo
export DATABASE_URL="postgres://..."
./scripts/p7_ci_pipeline.sh
```

This creates a fresh database, applies migrations, runs all proofs, and generates evidence artifacts.

## Running FlowVersion Conformance

```bash
cd workflow-graph/packages/flowversion-conformance
npm ci
npm test
npx flowversion-conformance test
```

## Principles

Both projects enforce:
- **No semantic privilege**: capabilities come from authenticated context, not JSON strings
- **Fail-closed defaults**: unknown states block, never pass silently
- **Deterministic proofs**: CI is the source of truth
- **Governance over governance**: rules that govern changing rules cannot be disabled by policy

## License

See LICENSE file.
