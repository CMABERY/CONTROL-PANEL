# User Manual — Governance Repository (CPO Governance Kernel + FlowVersion Conformance)

This manual covers **how to run, verify, and operate** the governance repository described by the canonical manifest. It is written for:
- **Developers** extending policies, proofs, or conformance tooling
- **Operators** running CI-style verification and database deployments
- **Auditors/reviewers** validating “what is authoritative” and “what is proven”

The repository is one of the “hard-physics” building blocks for **Agarthic IO**, a system-wide AI control plane with **Control / Execution / Evidence / Experience** layers. (This repo most directly maps to *Control* + *Evidence* disciplines.)  

## 0) What this repo is (and isn’t)

### What it is
- A **CPO Governance Kernel**: a Postgres-backed governance subsystem that enforces “single write aperture”, fail-closed gates, time-bounded exceptions, drift as ledger artifacts, and change control.
- A **FlowVersion conformance toolkit**: a Node-based conformance package (schema + goldens + tests) intended to keep contracts deterministic and non-duplicated.
- A **Keystone Gate envelope system**: canonical envelope schemas + operational gate wiring + conformance + replay (Phases 1–6) under `workflow-graph/packages/keystone-gate-runtime/`.
- A **machine-checkable evidence surface**:
  - `cpo/STATUS.json` = phase status + evidence links
  - `AUDIT_STAMP.json` = audit summary + authority hashes + verification commands
  - `REPO_MANIFEST.txt` = canonical structure listing

### What it is not (in this repository bundle)
- A complete multi-vendor **AI execution plane** (vendor adapters, retrieval pipeline, tool firewall, redaction/egress controls, unified console). Those are described as product goals, but are not evidenced as code in the manifest for this repo.

---

## 1) Repository layout (quick map)

At a high level (from the canonical manifest):

- **Repo root**
  - `.github/workflows/ci.yml` — CI entry
  - `AUDIT_STAMP.json` — audit + authority hashes
  - `REPO_MANIFEST.txt` — canonical structure
  - `cpo/` — CPO Governance Kernel (SQL + scripts + docs)
  - `workflow-graph/` — FlowVersion conformance + Keystone Gate runtime + reference domain adapter

Key “authority files” (treat these as load-bearing):
- `cpo/STATUS.json` — canonical phase status authority  
- `AUDIT_STAMP.json` — machine-checkable audit evidence  
- `workflow-graph/packages/flowversion-conformance/goldens.json` — FlowVersion contract truth source  

---

## 2) Prerequisites

### For FlowVersion conformance
- **Node.js** (recommend an LTS line consistent with your CI policy)
- `npm`

### For the CPO governance kernel
- A running **PostgreSQL** instance
- Ability to set `DATABASE_URL` (connection string) for the CI pipeline script

---

## 3) “One-command” verification (what CI should do)

`AUDIT_STAMP.json` provides the canonical verification commands.

### 3.1 Verify CPO kernel (database-backed proofs)
```bash
cd cpo
DATABASE_URL="postgres://USER:PASSWORD@HOST:5432/DBNAME" ./scripts/p7_ci_pipeline.sh
```

What this should do conceptually:
- apply migrations/patches as needed
- run proof queries that assert invariants
- fail if anything required is missing or bypassable (“no false-green”)

### 3.2 Verify FlowVersion conformance package
```bash
cd workflow-graph/packages/flowversion-conformance
npm ci
npm test
npm run validate
```

### 3.3 Dry-run the FlowVersion release script (no publish)
```bash
cd workflow-graph/packages/flowversion-conformance
ALLOW_PUBLISH=0 ./scripts/release.sh
```

---

## 4) Understanding CPO phases and what “complete” means

`cpo/STATUS.json` describes phases, their state, and evidence/proof files.

### Phase overview (as recorded in `STATUS.json`)
- **P1 — Contracts / Policy Check Registry**: integrated into P2 (registry behavior is embedded in the gate engine)
- **P2 — Persistence / Write Aperture**: single write aperture; append-only spine; registry-driven artifact table
- **P3 — Gate Integration / TOCTOU**: gate engine integration; closes semantic bypass and TOCTOU paths
- **P4 — Exception Expiry / Authority**: exceptions are time-bounded authority; enforced expiry (no “zombies”)
- **P5 — Drift Detection**: drift becomes ledger artifacts (dedupe deterministic; signals proven)
- **P6 — Change Control**: governance of governance; charter mutation treated as kernel physics
- **P7 — Release Closure Pipeline**: every commit re-proves the world (release closure discipline)

### Operational mantra (design intent you should preserve)
`STATUS.json` records the operating principles that should remain true even as code changes:
- Authority is authenticated.
- Physics outranks policy.
- Enumerations are structural.
- Evaluation is closed-world.
- Exceptions are expiring authority.
- Drift becomes ledger artifacts.
- Change control governs the rules.
- Every commit re-proves the world.

---

## 5) Operating the CPO Governance Kernel

This section is for operators/developers interacting with the DB-backed kernel.

### 5.1 Deployment and upgrades
The repo includes deployment scripts (see `cpo/scripts/` in the manifest), and SQL migrations/patches in `cpo/sql/`.

Typical workflow:
1. Ensure you have a database and credentials (set `DATABASE_URL`)
2. Run the CI pipeline script (P7) to apply and prove:
   - `./scripts/p7_ci_pipeline.sh`
3. If deploying in stages, use the provided deploy scripts (e.g., `deploy_p4.sh`, `deploy_p6.sh`) as your operational entry points.

### 5.2 Exceptions: “time-bounded authority”
Operationally:
- Exceptions are not “config flags”; they are **expiring authority**.
- Treat exception creation/renewal as a privileged action that should be audited and time-limited.

### 5.3 Drift detection
Drift is treated as a **ledger artifact**:
- detection should be deterministic
- dedupe should be deterministic
- drift should be queryable and attributable

### 5.4 Change control
Change control governs “the rules of the rules”:
- policy mutation should be treated as kernel-level action
- the system should remain fail-closed under misconfiguration

---

## 6) Using FlowVersion conformance (what it’s for)

The conformance package exists to prevent two common failures:
1. “It works on my machine” determinism drift
2. Duplicate truth sources (two goldens, two schemas, two competing contracts)

From the audit stamp, the repo asserts:
- **single goldens truth source** (no duplication)
- a CI workflow exists that enforces gates
- authority hashes are recorded for key files

### 6.1 When you should run it
- every PR that touches:
  - schema
  - canonicalization
  - goldens
  - adapter-loading behavior
- before any release/tagging step

### 6.2 What to look at when it fails
- schema test failures: contract drift
- golden mismatches: canonicalization drift or fixture drift
- validate failures: fixtures out of spec or inconsistent

---

## 7) Audit artifacts and “what is authoritative”

### 7.1 `REPO_MANIFEST.txt`
Purpose: canonical repository map (what files exist and where).

Use it to:
- confirm paths referenced by STATUS/proofs are present
- establish “this is the intended structure”

### 7.2 `AUDIT_STAMP.json`
Purpose: machine-checkable summary:
- file counts and breakdown
- hashes of authority files
- evidence link resolution status (all missing vs none missing)
- duplication audit (goldens count/locations)
- semantic bypass audit signals
- canonical verification commands

Use it as the **first-stop** for “what should I run?” and “what should be true?”

### 7.3 `cpo/STATUS.json`
Purpose: phase status authority with evidence links.

Use it to:
- answer “what’s complete?”
- find which SQL patches/proofs constitute evidence for a claim

---

## 8) Security and threat-modeling (how to use the security audit)

The included LLM security posture audit is not “runtime code,” but it is operationally useful as a control checklist:
- identify ingress/tool/egress/storage interception points
- treat tool calls and retrieved content as hostile surfaces
- treat logs as sensitive artifacts (retention, classification, access)

---

## 9) Troubleshooting

### “CPO pipeline fails to connect”
- Verify `DATABASE_URL` is set and reachable from your environment.
- Confirm the database user has privileges needed by the scripts/migrations.

### “Evidence links missing / manifests conflict”
- Start at `AUDIT_STAMP.json`:
  - if `all_evidence_resolves` is false, treat the repo state as non-verifiable until resolved
- Use `REPO_MANIFEST.txt` as the canonical expected structure and reconcile.

### “FlowVersion tests fail on CI but pass locally”
- Ensure Node/npm versions match your CI matrix.
- Prefer `npm ci` (clean install) over `npm install` in CI contexts.

### “Golden mismatch”
- Treat unexpected hash changes as a **bug**, not a “regen goldens” moment.
- If a contract change is intended, document it explicitly and update versioning policy (outside the scope of this repo bundle unless version constants exist).

---

## 10) Where this fits in Agarthic IO

`DoD (definition of done).md` defines the intended “publication-ready” pillars for Agarthic IO:
- Data Security & Privacy
- Control & Maintainability
- Auditability, Traceability & Replay
- Governance, Delegation & Agency
- Reliability, Evaluation & Drift Management
- Non-technical compatibility + dev-friendliness

This repository contributes strongest to:
- **Governance kernel physics** (Control Plane discipline)
- **Conformance + evidence discipline** (Evidence Plane discipline)

---

## Appendix A: Quick reference

### Verification commands (canonical)
- CPO pipeline:
  - `cd cpo && DATABASE_URL=... ./scripts/p7_ci_pipeline.sh`
- FlowVersion conformance:
  - `cd workflow-graph/packages/flowversion-conformance && npm ci && npm test && npm run validate`
- FlowVersion release dry-run:
  - `cd workflow-graph/packages/flowversion-conformance && ALLOW_PUBLISH=0 ./scripts/release.sh`

### Canonical authority files
- `cpo/STATUS.json`
- `AUDIT_STAMP.json`
- `workflow-graph/packages/flowversion-conformance/goldens.json`


---

## Keystone Gate quickstart (LOCKED)

Authoritative docs:

- `INTEGRATION_MANUAL.md`
- `docs/keystone/CANONICALIZATION_RULES.md`
- `docs/keystone/PHASE6_REPLAY_UI_SPEC.md`

Run Keystone Gate runtime tests:

```sh
cd workflow-graph
npm -w keystone-gate-runtime test
```
