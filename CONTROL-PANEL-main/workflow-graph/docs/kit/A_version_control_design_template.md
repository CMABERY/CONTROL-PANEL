# Version Control Design

**Link:** [https://chatgpt.com/c/697b24cc-dafc-8320-8a39-3542ebf293d6](https://chatgpt.com/c/697b24cc-dafc-8320-8a39-3542ebf293d6)  

## Prompt:
[SYSTEM]
You are a systems architect and interaction designer specializing in version control, collaborative workflows, and command-driven UX. Your job is to help me design and operationalize a “GitHub-for-{{YOUR_DOMAIN}}” system inspired by the Blockbase concept (Git-like commands executed natively inside an environment), but adapted to my actual environment, constraints, and collaboration needs.

Context / Inspiration (do not re-quote at length; extract mechanics and principles):
- A developer built “Git for Minecraft”: a native command prefix inside the game, enabling init/add/commit/log/reset/diff, plus a remote web app like GitHub.
- Key idea: builders collaborate on large, complex artifacts and need safe feature rollout, history, rollback, and clear diffs—even for 3D changes.

My Target Domain:
- Domain / environment: {{YOUR_DOMAIN}} (e.g., “an internal ops workflow builder”, “a modular prompt + agent system”, “a knowledge base”, “a game level editor”, “a configuration platform”, etc.)
- What is being versioned (the “world state” equivalent): {{VERSIONED_ARTIFACTS}}
- Typical collaborators/roles: {{ROLES_AND_PERMISSIONS}}
- Constraints (performance, storage, offline mode, security, audit, etc.): {{CONSTRAINTS}}
- Persistence assumptions (single session vs persistent backend): {{PERSISTENCE_MODEL}}
- Integrations desired (web UI, GitHub, S3, DB, etc.): {{INTEGRATIONS}}

Mission:
Design a complete, implementable “version control + collaboration” interaction model for {{YOUR_DOMAIN}} that feels as native and ergonomic as Blockbase felt inside Minecraft.

Hard Requirements:
1) Provide a concept mapping from Git → {{YOUR_DOMAIN}} equivalents (repo, working tree, staging area, commit, branch, merge, remote, pull request, tags/releases).
2) Define a minimal command protocol (human-typable) and response format (machine-readable) that can work in chat/CLI/UI.
3) Specify a data model for state, diffs, commits, and metadata (including authorship, timestamps, and optional signatures).
4) Define how “diff” works in this domain (including a visualization strategy if the domain is not 2D text).
5) Handle collaboration realities: conflicts, merges, permissions, audit logs, and rollback safety.
6) Produce an MVP plan and a v2 plan with clear milestones and test strategy.
7) Keep assumptions explicit. If a detail truly depends on my domain, propose 2–3 viable options and state tradeoffs; do not stall on questions.

Output Format:
Deliver your response in the following sections, with headers exactly as written.

SECTION A — Extracted Design Principles (from Blockbase → general patterns)
- Summarize the mechanics worth copying (native commands, staging, history, reset, diff visualization, remote)
- Summarize the collaboration problems it solved and why those matter in {{YOUR_DOMAIN}}

SECTION B — Git-to-Domain Concept Map
Provide a table:
Git Concept | Meaning in Git | Equivalent in {{YOUR_DOMAIN}} | Notes / Pitfalls

SECTION C — Interaction Protocol (Commands + Semantics)
Define:
- Command prefix (e.g., “bb”, “vc”, or domain-branded)
- Command syntax and examples for:
  init, status, add/stage, commit, log, diff, reset (soft/mixed/hard equivalents), branch, checkout/switch, merge, revert, stash (optional), tag/release, remote add/list, push/pull/fetch
- Error handling rules (invalid state, conflicts, permission denial)
- Idempotency rules (what can be safely repeated)
- A “help” and “explain” command for discoverability

SECTION D — State + Data Model
Specify:
- Objects (commit, tree/snapshot, change set, blob/asset, references/branches, remotes)
- Metadata fields (author, message, timestamps, parent commits, hashes/IDs)
- Storage approach options (snapshots vs deltas vs hybrid)
- How to generate stable IDs/hashes (and when not to)
- Security/audit considerations (immutability, signing, tamper evidence)

SECTION E — Diff & Merge Strategy (Domain-Specific)
Define:
- What counts as an “addition / deletion / modification” in {{YOUR_DOMAIN}}
- How diffs are computed (structural diff, semantic diff, event-sourcing diff, etc.)
- Visualization strategy:
  - In a UI: how changes are highlighted
  - In text-only contexts: how diffs are summarized
- Merge strategy:
  - Automatic merge rules (when safe)
  - Conflict detection
  - Conflict resolution UX (human workflow + AI assistance boundaries)
- Safety rails:
  - Protected branches / approvals
  - Rollback strategy and “blast radius” containment

SECTION F — Remote Collaboration Model (“GitHub equivalent”)
Design:
- Remote repository concept and URLs/IDs
- Auth model (SSO, tokens, roles)
- Pull request / review flow (if applicable)
- Policies: branch protection, required checks, CI hooks, provenance
- Activity feed / audit log requirements

SECTION G — MVP Build Plan + Tests
Provide:
- MVP scope: the smallest complete usable product
- v2/v3 expansions
- Implementation milestones (backend + client)
- Test plan:
  - Unit tests for diff/merge
  - Property-based tests (if relevant)
  - Load/perf tests
  - Security tests
  - Realistic scenarios (multi-user conflicts, rollback after bad deploy)

SECTION H — Worked Example (End-to-End)
Give a concrete scenario using {{YOUR_DOMAIN}}:
- init repo
- make changes
- stage and commit
- view log
- show diff
- create a branch
- merge and resolve a conflict
- push to remote
Include both:
1) The commands a user would type
2) The structured responses the system would return (use JSON)

Constraints:
- Do not give a generic essay. I want a design I can implement.
- Do not rely on Minecraft specifics; use it as inspiration only.
- Avoid inventing “magic” capabilities; whenever an AI assist feature is proposed, specify what data it needs and its failure modes.
- Keep the design consistent across sections (names, objects, commands must match).

## Response:
Thought for 16m 15s

SECTION A — Extracted Design Principles (from Blockbase → general patterns)
---------------------------------------------------------------------------

### Mechanics worth copying

*   **Native, in-environment commands**  
    Make version control feel like part of the environment’s “physics,” not an external ceremony. The command surface should be small, memorable, and consistent.
*   **Three-layer mental model (Working → Staging → History)**  
    The staging area is the secret sauce for safe, partial commits and clean collaboration. People rarely want to commit _everything_ they poked.
*   **History as a first-class navigation tool**  
    Fast `log`, `show`, and “time travel” (`reset`, `checkout`, `revert`) reduce fear and encourage experimentation.
*   **Diff that matches the medium**  
    Text diff works for code because code is linear text. For non-text artifacts (graphs, configs, prompts, layouts), diff must be **structural** and **visual**, not just “JSON vomit.”
*   **Remote as a social layer (GitHub-like)**  
    The remote isn’t just storage; it’s where collaboration becomes legible: reviews, permissions, branch protection, provenance, and audit.

### Collaboration problems it solved (and why they matter in your domain)

Blockbase-style workflows matter whenever collaborators are changing **a shared stateful artifact** that:

*   is large and interdependent (changes ripple),
*   needs safe rollout (feature branches / staged merges),
*   needs rollback (bad changes happen on Fridays),
*   needs accountability (who changed what, when, and why),
*   needs conflict handling (parallel edits are inevitable).

### Explicit assumptions (so this is implementable now)

Your placeholders weren’t filled in, so I’m instantiating a concrete default that is broadly reusable:

**Default target domain (used consistently below):**  
**An internal ops workflow builder** (a node/edge graph editor for automation).

*   **{{YOUR\_DOMAIN}}:** Workflow builder (graph-based)
*   **{{VERSIONED\_ARTIFACTS}}:** Workflows (DAGs), node configs, connectors, secrets references (not secrets themselves), templates, test fixtures, deployment manifests
*   **{{ROLES\_AND\_PERMISSIONS}}:** Viewer, Editor, Maintainer, Admin, Auditor; plus environment-scoped deploy permissions
*   **{{CONSTRAINTS}}:** Large graphs, audit requirements, partial offline mode, strict access control, “secrets never in commits,” deterministic diffs
*   **{{PERSISTENCE\_MODEL}}:** Local workspace + persistent backend (remote). Offline commits allowed; push later.
*   **{{INTEGRATIONS}}:** Web UI, API/CLI, optional GitHub export, object storage (S3/GCS) for blobs, Postgres for metadata, OIDC/SSO

If your actual domain differs, two viable swaps (tradeoffs):

1.  **Modular prompt + agent system**: artifacts are prompt modules + tool configs + agent graphs; diff/merge similar (graph + text).
2.  **Knowledge base / structured docs**: artifacts are pages + embeddings + metadata; diff more text/field-based; merges closer to Git.

Everything below still holds; only the diff/merge “shape” changes slightly.

* * *

SECTION B — Git-to-Domain Concept Map
-------------------------------------

| Git Concept | Meaning in Git | Equivalent in {{YOUR\_DOMAIN}} (Workflow Builder) | Notes / Pitfalls |
| --- | --- | --- | --- |
| Repository | Project container for history | **Workspace Repo** (Workflow project) | Repo can hold multiple workflows; treat each workflow as a “top-level path.” |
| Working tree | Your local modified files | **Working Graph** (current editable workflows) | Must support “dirty state” detection across graph + assets. |
| Staging area (index) | Selected changes to commit | **Staging Patch** (selected node/edge/config changes) | Partial staging needs selectors (by node, edge, subfield). |
| Commit | Snapshot + metadata | **Graph Commit** (snapshot or delta + metadata) | Ensure deterministic serialization/canonicalization. |
| Branch | Movable pointer to commits | **Branch** (e.g., `main`, `feature/*`) | Also support environment branches like `prod` as protected refs. |
| Merge | Combine histories | **3-way Graph Merge** | Hard part: stable node identity and conflict UX. |
| Rebase | Replay commits onto new base | **Optional v2**: “rebase” for clean history | Can be dangerous; keep out of MVP unless needed. |
| Remote | Another repo location | **Remote Repo** (FlowHub) | Needs auth, permissions, audit, PRs. |
| Pull request | Reviewed merge request | **Change Request (CR/PR)** | Attach previews, diff visualization, checks (lint/sim). |
| Tag/Release | Named pointer, version | **Release Tag** (e.g., `v1.2.0`) | Tie to deployment artifact hashes; immutable. |
| Reset (soft/mixed/hard) | Move HEAD / index / working | **Reset HEAD / Stage / Working Graph** | Must prevent accidental destructive resets (guardrails). |
| Revert | New commit undoing changes | **Revert Commit** | Safer than reset on shared branches. |
| Stash | Temporary shelve working changes | **Stash Patch** | Useful in UI-heavy editing; optional in MVP. |
| Diff | Show changes | **Graph Diff** (nodes/edges/fields + visual overlay) | Don’t rely on raw JSON diff; it’s unreadable at scale. |

* * *

SECTION C — Interaction Protocol (Commands + Semantics)
-------------------------------------------------------

### Command prefix

*   **Prefix:** `fv` (short for **Flow Version**)
*   In environments that already have slash commands, support: `/fv …` as an alias.

### Command format

```
fv <verb> [noun] [selectors...] [flags]
```

### Response format (machine-readable, works in chat/CLI/UI)

All commands return a single JSON object.

**Envelope:**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "Human-readable summary.",
  "data": {},
  "meta": {
    "request_id": "req_01HV...",
    "timestamp": "2026-01-29T18:22:10-08:00"
  }
}
```

**Errors:**

```json
{
  "ok": false,
  "code": "FV409_CONFLICT",
  "message": "Merge conflicts detected.",
  "data": { "conflicts": [/*...*/] },
  "meta": { "request_id": "...", "timestamp": "..." }
}
```

### Selectors (critical for partial staging & targeted operations)

Selectors identify subparts of a workflow graph:

*   `wf:<workflow_id>` (or `wf:"Name"`)
*   `node:<node_id>`
*   `edge:<from_node_id>-><to_node_id>`
*   `field:<node_id>.<json_pointer>` (e.g., `field:n42./config/timeout_ms`)
*   `path:<repo_path>` (when repo contains files/templates)

### Commands (syntax + examples)

#### `init`

Create a repo in the current project/workspace.

```
fv init --name "Payments Automations"
```

#### `status`

Show working vs staged vs HEAD summary.

```
fv status
```

#### `add` / stage

Stage changes by selector (or everything).

```
fv add --all
fv add wf:payments_refunds
fv add node:n42
fv add field:n42./config/timeout_ms
```

#### `commit`

Create a commit from staged changes.

```
fv commit -m "Add fraud-check step and increase timeout"
fv commit -m "Hotfix: correct retry policy" --sign
```

#### `log`

Show history.

```
fv log --limit 20
fv log wf:payments_refunds
```

#### `show`

Show a commit (metadata + diff summary).

```
fv show cmt_01HX...
```

#### `diff`

Compare states. Defaults: working vs HEAD.

```
fv diff
fv diff --staged
fv diff --base HEAD~1 --target HEAD
fv diff --cr CR_1042
```

#### `reset` (soft/mixed/hard equivalents)

*   **soft:** move HEAD only (keep staged + working)
*   **mixed:** move HEAD + staging (keep working)
*   **hard:** move HEAD + staging + working (destructive)

```
fv reset --soft HEAD~1
fv reset --mixed HEAD~1
fv reset --hard HEAD~1
```

Guardrail: require `--hard --force` unless on a private, unpushed branch.

#### `branch`

```
fv branch
fv branch create feature/fraud-check
fv branch delete feature/old-experiment
```

#### `switch` / `checkout`

```
fv switch feature/fraud-check
fv switch main
```

#### `merge`

```
fv merge main
fv merge feature/fraud-check
```

If conflicts:

*   returns `FV409_CONFLICT` with conflict objects
*   user resolves via `fv resolve …` then `fv merge --continue`

#### `resolve` (conflict resolution)

```
fv resolve --list
fv resolve node:n42 --take ours
fv resolve field:n42./config/retry_policy --take theirs
fv resolve node:n77 --edit   (opens UI editor; in CLI returns an instruction payload)
fv merge --continue
```

#### `revert`

Creates a new commit that undoes a prior commit.

```
fv revert cmt_01HX...
```

#### `stash` (optional)

```
fv stash push -m "WIP: branching experiment"
fv stash list
fv stash pop stash_03
```

#### `tag` / `release`

```
fv tag create v1.4.0 --commit HEAD --notes "Add fraud check + alerts"
fv tag list
```

#### Remotes

```
fv remote add origin flowhub://acme/payments-automations
fv remote list
```

#### `fetch` / `pull` / `push`

```
fv fetch origin
fv pull origin main
fv push origin feature/fraud-check
fv push origin main
```

### Error handling rules

*   **Invalid state:**
    *   committing with nothing staged ⇒ `FV400_NOTHING_STAGED`
    *   switching branches with dirty working graph ⇒ `FV409_DIRTY_WORKTREE` (suggest commit/stash)
*   **Conflicts:** `FV409_CONFLICT` with structured conflict list
*   **Permission denial:** `FV403_FORBIDDEN` including required role/capability
*   **Protected branch:** `FV423_PROTECTED_REF` (requires PR / approvals)

### Idempotency rules

*   Safe to repeat:
    *   `status`, `log`, `diff`, `show`, `branch` (read-only)
    *   `remote add` is idempotent if same URL/name (else error `FV409_REMOTE_EXISTS`)
    *   `add` is idempotent (staging same patch twice yields same index)
    *   `fetch` idempotent (no-op if up-to-date)
*   Not idempotent by default:
    *   `commit` (creates new commit ID each time unless `--reuse-message --allow-empty` is specified)
    *   `merge --continue` (only valid when merge state exists)

### Discoverability

*   `fv help` (lists commands + short usage)
*   `fv explain <concept>` (domain-aware help)
    *   examples: `fv explain staging`, `fv explain conflicts`, `fv explain protected-branches`

* * *

SECTION D — State + Data Model
------------------------------

### Core objects

#### Commit

Represents a versioned change.

*   **Fields**
    *   `commit_id` (content-addressed hash or ULID + hash)
    *   `parents[]`
    *   `author` `{user_id, display_name}`
    *   `committer` (optional, for bots)
    *   `timestamp`
    *   `message`
    *   `tree_id` (points to snapshot root) or `delta_id`
    *   `changeset_id` (normalized diff summary)
    *   `signatures[]` (optional)
    *   `metadata` (labels, ticket refs, environment intent)

#### Tree / Snapshot

A deterministic representation of repo state at a commit.

*   For workflow builder, the tree contains:
    *   workflows (graph JSON)
    *   templates
    *   schema versions
    *   references to large blobs

#### Blob / Asset

Large or binary content (icons, test payloads, exported bundles).

*   Stored in object storage (S3/GCS) keyed by hash.
*   Commits store **references** (hash + size + mime), not raw bytes.

#### Change Set

Normalized diff with semantic categories.

*   node add/remove/modify
*   edge add/remove
*   field patch (JSON Patch / JSON Pointer)
*   rename/move operations (if supported)

#### Refs (branches/tags)

*   `ref_name` (e.g., `refs/heads/main`, `refs/tags/v1.2.0`)
*   `commit_id`
*   `ref_metadata` (protection rules, required checks)

#### Remotes

*   `remote_name` (e.g., `origin`)
*   `url` (e.g., `flowhub://org/repo`)
*   `auth_binding` (token, OIDC, device flow)

### Storage approach options (pick one; all are valid)

1.  **Snapshot per commit (simple, heavy)**
    *   Pros: simplest reads, easiest correctness
    *   Cons: storage grows fast for large graphs
    *   MVP-friendly if graphs are moderate and compression is good
2.  **Delta per commit (efficient, complex)**
    *   Pros: smaller storage
    *   Cons: reconstructing state requires applying deltas; needs periodic compaction
3.  **Hybrid (recommended)**
    *   Store deltas for most commits
    *   Create periodic snapshots (e.g., every N commits or on release tags)
    *   Pros: balanced performance + storage, common in real systems

### Stable IDs / hashes

*   **Node IDs must be stable** across edits (`node_id` as UUID/ULID), not derived from position or label.
*   **Canonicalization** is mandatory:
    *   sort keys
    *   normalize arrays where order is not semantic
    *   strip ephemeral UI fields (viewport position may be semantic _or not_; decide explicitly)
*   **Hashing approach**
    *   `tree_id = sha256(canonical_tree_bytes)`
    *   `commit_id = sha256(commit_header + tree_id + parents…)` (Git-like Merkle properties)
*   When _not_ to hash:
    *   Don’t include secret material
    *   Don’t include volatile runtime data (last-run timestamps, execution logs)

### Security / audit considerations

*   **Immutability:** commits are append-only; refs are the only movable pointers.
*   **Signing (optional but real):**
    *   `--sign` uses Ed25519 signatures over `(commit_id || tree_id || parents || timestamp)`
    *   Store public keys per user; integrate with SSO provisioning.
*   **Tamper evidence:**
    *   Merkle chaining (parents) + signatures
    *   Server enforces “no commit mutation,” only new commits.
*   **Secrets policy:**
    *   Commits store _references_ to secrets (vault key IDs), never secret values.
    *   Diff tooling must redact secret-reference details if needed (policy-driven).

* * *

SECTION E — Diff & Merge Strategy (Domain-Specific)
---------------------------------------------------

### What counts as add / delete / modify in a workflow builder

*   **Addition**
    *   new node
    *   new edge
    *   new workflow (file-like unit)
*   **Deletion**
    *   node removed
    *   edge removed
    *   workflow removed
*   **Modification**
    *   node config fields changed (timeouts, retries, endpoint, mapping)
    *   edge routing conditions changed
    *   node type changed (often treated as delete+add unless explicitly supported)
    *   workflow metadata changed (name, triggers, schedules)

### How diffs are computed

Use a **semantic graph diff** rather than raw JSON diff.

1.  **Identity matching**
    *   nodes matched by `node_id`
    *   edges matched by `(from_id, to_id, edge_key)` where `edge_key` disambiguates parallel edges
2.  **Field-level diff**
    *   config objects diffed using JSON Pointer paths
    *   optionally classify fields: `behavioral`, `cosmetic`, `security-sensitive`
3.  **Output format (internal)**
    *   `changeset = { node_added[], node_removed[], node_modified[], edge_added[], edge_removed[] }`
    *   node\_modified includes `field_patches[]` (JSON Patch ops) + summary

### Visualization strategy

#### In a UI

*   **Overlay highlights on the graph canvas**
    *   added nodes: “glow” + badge
    *   removed nodes: shown as ghosted silhouettes (optional) in a “before” layer
    *   modified nodes: corner badge with count of changed fields
    *   edges: colored or dashed based on add/remove/modify
*   **Side panel “Change List”**
    *   grouped by workflow → node → field
    *   click jumps to node and shows before/after for that node’s config

#### In text-only contexts (chat/CLI)

Provide a compact summary + expandable detail:

*   Summary example:
    *   `+2 nodes, +3 edges, ~1 node modified (2 fields)`
*   Detail example:
    *   `~ node:n42 (HTTP Request) field /config/timeout_ms: 2000 -> 5000`
    *   `+ edge:n10->n42 (success)`
    *   `- node:n77 (Slack Notify)`

### Merge strategy

#### Automatic merge rules (safe cases)

3-way merge with base `B`, ours `O`, theirs `T`:

*   If a field changed only in one side (O vs B, T unchanged) ⇒ take change
*   If different fields changed on same node ⇒ merge both
*   If edges added in one side only ⇒ add edges
*   If same edge added in both sides identically ⇒ keep once (idempotent)

#### Conflict detection (common cases)

*   Same field changed differently in O and T
*   Node deleted in one side, modified in the other
*   Node type changed differently
*   Schema version mismatch requiring migration
*   Edge rewired in both sides affecting same connection point

Conflicts are returned as structured objects:

```json
{
  "conflict_id": "cx_01",
  "scope": "field",
  "selector": "field:n42./config/timeout_ms",
  "base": 2000,
  "ours": 5000,
  "theirs": 3000,
  "severity": "behavioral"
}
```

#### Conflict resolution UX (human workflow + AI assistance boundaries)

*   **Human-first**: the system must allow deterministic choices:
    *   take ours / take theirs / manual edit
*   **AI assistance (optional, non-magical)**
    *   Allowed inputs: base/ours/theirs values, node schema, validation rules, downstream dependency graph, tests/evals results
    *   Outputs: _suggestion_ + rationale + confidence + a proposed patch
    *   Failure modes:
        *   suggests invalid config (caught by schema validation)
        *   suggests semantically wrong behavior (caught by simulation/tests only)
    *   The system must never auto-apply AI suggestions without explicit user action.

### Safety rails

*   **Protected branches**
    *   `main`, `prod/*` require PR + approvals + passing checks
*   **Required checks**
    *   schema validation
    *   lint rules (e.g., “no unbounded retries”)
    *   workflow simulation (dry-run)
*   **Rollback strategy**
    *   prefer `revert` commits on shared branches
    *   releases/tags allow “deploy previous known-good tree\_id”
*   **Blast radius containment**
    *   environment-scoped deploy permissions
    *   per-workflow ownership
    *   change impact view: show affected triggers, downstream workflows, connected systems

* * *

SECTION F — Remote Collaboration Model (“GitHub equivalent”)
------------------------------------------------------------

### Remote repository concept and URLs/IDs

*   Remote service: **FlowHub**
*   Repo URL scheme: `flowhub://<org>/<repo>`
*   Internal IDs:
    *   `repo_id` (ULID)
    *   `commit_id` (hash)
    *   `cr_id` (change request)

### Auth model

*   **SSO via OIDC/SAML** for interactive users
*   **Tokens** for automation (scoped, expiring)
*   **Roles**
    *   Viewer: read
    *   Editor: create branches/commits, push to non-protected refs
    *   Maintainer: merge PRs, manage branch rules
    *   Admin: repo settings, retention, keys
    *   Auditor: read + audit exports, cannot modify

### Pull request / review flow

*   Create CR from branch to base:
    *   includes: diff summary, visual graph diff, checks status, discussion thread
*   Reviewers can:
    *   comment on nodes/fields (inline)
    *   request changes
    *   approve
*   Merge options:
    *   merge commit (default)
    *   squash (optional)
    *   rebase (optional, v2)

### Policies

*   Branch protection:
    *   required reviewers count
    *   required checks
    *   signed commits required (optional)
    *   restrict who can push directly
*   CI hooks (domain checks):
    *   schema validation
    *   simulation/dry-run
    *   integration test harness (mocked endpoints)
*   Provenance:
    *   record tool version, schema version, and optional “generated-by” metadata
    *   attach artifacts (simulation results) to commits/CRs as immutable blobs

### Activity feed / audit log requirements

Audit must be queryable and exportable:

*   who pushed what ref
*   who merged what CR
*   who changed permissions
*   who triggered deployments of which tag/commit/tree\_id
*   immutable event log with server-side timestamps

* * *

SECTION G — MVP Build Plan + Tests
----------------------------------

### MVP scope (smallest complete usable product)

**Goal:** single repo, multiple workflows, local editing, commit history, diff, branches, push/pull, PRs with review, safe merge.

**MVP features**

*   Local repo concepts:
    *   working graph, staging patch, commits, branches
*   Commands:
    *   `init/status/add/commit/log/diff/branch/switch/merge/resolve/remote/push/pull`
*   Diff:
    *   semantic graph diff + text summary
    *   basic UI overlay in web app (graph highlights + change list)
*   Remote:
    *   auth, repo hosting, push/pull
    *   Change Requests with approvals + required checks
*   Checks:
    *   schema validation + basic lints
*   Secrets:
    *   secret references only; enforce at commit time

### v2 plan (high-value expansions)

*   `stash`, `revert`, `tag/release`
*   richer merge tools:
    *   per-node interactive resolver
    *   better rename/move detection
*   simulations:
    *   deterministic dry-run with fixtures
    *   attach results to commits/CRs
*   signing enforcement + key management UI
*   retention policies + snapshot compaction (hybrid storage)

### v3 plan (advanced)

*   rebase + cherry-pick
*   partial clone / sparse checkout (large repos)
*   cross-repo dependencies (workflow modules)
*   policy-as-code for branch rules + checks
*   AI assist for conflict suggestions + change impact analysis (opt-in, logged)

### Implementation milestones (backend + client)

1.  **Canonical model + hashing**
    *   define canonical graph JSON
    *   implement tree hashing + commit object
2.  **Local engine**
    *   working/staging/commit refs
    *   add/stage selectors
3.  **Diff engine**
    *   graph semantic diff
    *   JSON patch generation for fields
4.  **Merge engine**
    *   3-way merge + conflict objects
    *   resolve commands
5.  **Remote service**
    *   repo storage, ref updates, auth
    *   push/pull protocol (pack-like bundles or API-based)
6.  **CR UI**
    *   visual diff
    *   review, approvals, merge gating
7.  **Checks runner**
    *   validation + lint + simulation hooks

### Test plan

#### Unit tests

*   canonicalization (same graph → same bytes/hash)
*   diff correctness (known inputs → expected changeset)
*   merge rules (3-way merge cases)

#### Property-based tests (very relevant here)

Generate random graphs and random edit sequences:

*   invariant: applying diff from A→B to A yields B
*   invariant: merge(base, ours, theirs) equals ours when theirs==base
*   invariant: conflict detection triggers only when overlapping edits occur
*   invariant: hash stability under non-semantic reorderings

#### Load/perf tests

*   diff/merge time on large graphs (10k nodes)
*   remote push/pull on large change sets
*   UI rendering of diff overlays

#### Security tests

*   permission enforcement on protected refs
*   secret leakage prevention (attempt commits containing secret values)
*   audit log immutability checks
*   signature verification and key rotation scenarios

#### Realistic scenarios

*   two editors modify adjacent nodes → clean merge
*   two editors modify same timeout field → conflict + resolve
*   rollback after bad deploy: revert release commit and redeploy prior tag
*   offline commit then push with remote drift → pull/rebase/merge flow

* * *

SECTION H — Worked Example (End-to-End)
---------------------------------------

**Scenario:** Two collaborators are editing the `payments_refunds` workflow. One adds a fraud-check node on a feature branch. Another changes retry policy on `main`. We merge and resolve a conflict on a shared field.

### 1) init repo

**Command**

```bash
fv init --name "Payments Automations"
```

**Response**

```json
{
  "ok": true,
  "code": "FV201",
  "message": "Initialized repo 'Payments Automations'. Default branch is 'main'.",
  "data": {
    "repo_id": "repo_01J1A2B3C4D5E6F7G8",
    "default_branch": "main"
  },
  "meta": {
    "request_id": "req_01J1A2X0H9",
    "timestamp": "2026-01-29T10:00:00-08:00"
  }
}
```

### 2) make changes (editing happens in the builder UI)

User adds a node `Fraud Check` (`node_id=n42`) and connects it.

### 3) stage and commit

**Command**

```bash
fv status
```

**Response**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "Working graph has uncommitted changes. Nothing staged.",
  "data": {
    "branch": "main",
    "head": "cmt_000000000000000000",
    "staged": { "summary": { "nodes_added": 0, "nodes_removed": 0, "nodes_modified": 0, "edges_added": 0, "edges_removed": 0 } },
    "working": { "summary": { "nodes_added": 1, "nodes_removed": 0, "nodes_modified": 0, "edges_added": 2, "edges_removed": 0 } }
  },
  "meta": { "request_id": "req_01J1A2X0HA", "timestamp": "2026-01-29T10:02:10-08:00" }
}
```

**Command**

```bash
fv add wf:payments_refunds
```

**Response**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "Staged changes for workflow 'payments_refunds'.",
  "data": {
    "staged": {
      "summary": { "nodes_added": 1, "nodes_removed": 0, "nodes_modified": 0, "edges_added": 2, "edges_removed": 0 }
    }
  },
  "meta": { "request_id": "req_01J1A2X0HB", "timestamp": "2026-01-29T10:02:25-08:00" }
}
```

**Command**

```bash
fv commit -m "Add fraud-check step to refunds workflow"
```

**Response**

```json
{
  "ok": true,
  "code": "FV201",
  "message": "Committed: Add fraud-check step to refunds workflow",
  "data": {
    "commit_id": "cmt_01J1A2Z9KQ",
    "branch": "main",
    "changeset": { "nodes_added": ["n42"], "edges_added": ["n10->n42:success", "n42->n11:success"] }
  },
  "meta": { "request_id": "req_01J1A2X0HC", "timestamp": "2026-01-29T10:03:00-08:00" }
}
```

### 4) view log

**Command**

```bash
fv log --limit 5
```

**Response**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "Showing last 1 commit on main.",
  "data": {
    "commits": [
      {
        "commit_id": "cmt_01J1A2Z9KQ",
        "author": { "user_id": "u_123", "display_name": "Boss" },
        "timestamp": "2026-01-29T10:03:00-08:00",
        "message": "Add fraud-check step to refunds workflow",
        "parents": ["cmt_000000000000000000"]
      }
    ]
  },
  "meta": { "request_id": "req_01J1A2X0HD", "timestamp": "2026-01-29T10:03:10-08:00" }
}
```

### 5) show diff

**Command**

```bash
fv diff --base HEAD~1 --target HEAD
```

**Response**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "+1 node, +2 edges in workflow 'payments_refunds'.",
  "data": {
    "diff": {
      "workflows": [
        {
          "workflow_id": "payments_refunds",
          "summary": { "nodes_added": 1, "nodes_removed": 0, "nodes_modified": 0, "edges_added": 2, "edges_removed": 0 },
          "nodes_added": [
            { "node_id": "n42", "type": "FraudCheck", "label": "Fraud Check" }
          ],
          "edges_added": [
            { "from": "n10", "to": "n42", "edge_key": "success" },
            { "from": "n42", "to": "n11", "edge_key": "success" }
          ]
        }
      ]
    }
  },
  "meta": { "request_id": "req_01J1A2X0HE", "timestamp": "2026-01-29T10:03:30-08:00" }
}
```

### 6) create a branch

**Command**

```bash
fv branch create feature/fraud-tuning
fv switch feature/fraud-tuning
```

**Response**

```json
{
  "ok": true,
  "code": "FV201",
  "message": "Created branch 'feature/fraud-tuning' at cmt_01J1A2Z9KQ and switched to it.",
  "data": {
    "branch": "feature/fraud-tuning",
    "head": "cmt_01J1A2Z9KQ"
  },
  "meta": { "request_id": "req_01J1A2X0HF", "timestamp": "2026-01-29T10:04:00-08:00" }
}
```

User edits node `n42` timeout from `2000` → `5000` and stages/commits.

**Command**

```bash
fv add field:n42./config/timeout_ms
fv commit -m "Increase fraud-check timeout to 5000ms"
```

**Response**

```json
{
  "ok": true,
  "code": "FV201",
  "message": "Committed: Increase fraud-check timeout to 5000ms",
  "data": {
    "commit_id": "cmt_01J1A3AA77",
    "branch": "feature/fraud-tuning",
    "changeset": {
      "nodes_modified": [
        {
          "node_id": "n42",
          "field_patches": [
            { "op": "replace", "path": "/config/timeout_ms", "from": 2000, "value": 5000 }
          ]
        }
      ]
    }
  },
  "meta": { "request_id": "req_01J1A2X0HG", "timestamp": "2026-01-29T10:05:00-08:00" }
}
```

Meanwhile, another collaborator on `main` changes that same field to `3000ms` and pushes to remote (simulated here as already happened).

### 7) merge and resolve a conflict

First, update local `main`:  
**Command**

```bash
fv switch main
fv pull origin main
```

**Response**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "Updated main from origin. Fast-forwarded 1 commit.",
  "data": {
    "branch": "main",
    "head": "cmt_01J1A3BEEF"
  },
  "meta": { "request_id": "req_01J1A2X0HH", "timestamp": "2026-01-29T10:06:00-08:00" }
}
```

Now merge feature branch into main:  
**Command**

```bash
fv merge feature/fraud-tuning
```

**Response (conflict)**

```json
{
  "ok": false,
  "code": "FV409_CONFLICT",
  "message": "Merge conflicts detected in workflow 'payments_refunds'.",
  "data": {
    "merge": {
      "base": "cmt_01J1A2Z9KQ",
      "ours": "cmt_01J1A3BEEF",
      "theirs": "cmt_01J1A3AA77"
    },
    "conflicts": [
      {
        "conflict_id": "cx_01",
        "scope": "field",
        "selector": "field:n42./config/timeout_ms",
        "base": 2000,
        "ours": 3000,
        "theirs": 5000,
        "severity": "behavioral"
      }
    ]
  },
  "meta": { "request_id": "req_01J1A2X0HI", "timestamp": "2026-01-29T10:06:20-08:00" }
}
```

Resolve by taking “theirs” (5000ms):  
**Command**

```bash
fv resolve field:n42./config/timeout_ms --take theirs
fv merge --continue
```

**Response**

```json
{
  "ok": true,
  "code": "FV201",
  "message": "Merge completed with 1 conflict resolved. Created merge commit on main.",
  "data": {
    "branch": "main",
    "commit_id": "cmt_01J1A3C0DE",
    "resolved_conflicts": ["cx_01"]
  },
  "meta": { "request_id": "req_01J1A2X0HJ", "timestamp": "2026-01-29T10:07:00-08:00" }
}
```

### 8) push to remote

**Command**

```bash
fv push origin main
```

**Response**

```json
{
  "ok": true,
  "code": "FV200",
  "message": "Pushed main to origin.",
  "data": {
    "remote": "origin",
    "ref": "refs/heads/main",
    "new_head": "cmt_01J1A3C0DE"
  },
  "meta": { "request_id": "req_01J1A2X0HK", "timestamp": "2026-01-29T10:07:20-08:00" }
}
```

* * *

This design is intentionally “boring in the right ways”: semantic diff, deterministic IDs, conflict objects, protected refs, and an interaction protocol you can ship without inventing wizardry. The only “fancy” part—AI assistance—is strictly optional and bounded by schema validation + explicit user action.

## Prompt:
## Flow Version (fv) spec review: what’s strong, what will bite, and what to tighten

You’ve basically built “Git, but for graphs” without falling into the two classic traps:

1. pretending JSON diff is readable, and
2. letting “AI magic” quietly become “AI made a production change and nobody knows why.”

Below is a design review aimed at making this shippable with fewer “surprise, we invented a new kind of merge hell” moments.

---

## What’s already solid (keep it)

### 1) The **Working → Staging → History** model

That’s the whole game. Especially for UI-heavy artifacts, partial staging is the difference between “I trust this system” and “I’m scared to click things.”

### 2) Selectors down to field granularity

field:n42./config/timeout_ms is the right abstraction. It also becomes your backbone for:

* conflict objects
* inline review comments
* audit queries
* “what changed?” summaries

### 3) Conflict objects are structured (not vibes)

Returning a conflict list with base/ours/theirs is exactly how you keep merges deterministic and debuggable.

### 4) “Secrets never in commits” is explicit

And you correctly treat secrets as references, not bytes. That’s not optional in real orgs.

---

## Decisions you should make explicit (or you’ll make them accidentally later)

### A) Canonicalization: define “semantic equality” precisely

Right now you say “sort keys, normalize arrays where order is not semantic.” That’s correct but incomplete unless you **declare** which arrays are semantic.

In graph artifacts, the common landmines:

* **Node list order**: should be non-semantic → canonical sort by node_id.
* **Edges list order**: non-semantic → canonical sort by (from, to, edge_key).
* **Ports / handles**: sometimes semantic (e.g., “left port vs right port”)—must be encoded, not implied.
* **UI layout** (x,y, viewport): decide one of:

  1. **Semantic** (versioned) because layout is part of the artifact users care about, OR
  2. **Non-semantic** (excluded), OR
  3. **Split-brain**: two tracks (behavioral vs presentation) with separate diffs, separate merge policies.

If you don’t choose, users will. And users choose chaos.

**Recommendation (practical):** split behavioral vs presentation fields. Default diff/PR shows behavioral first, presentation collapsible.

---

### B) Staging semantics: your “index” must freeze values

In Git, staging isn’t “a set of filenames,” it’s “the exact blob content at stage time.”

With graphs, staging must similarly freeze:

* a staged snapshot for selected nodes/fields, or
* a staged patch that includes **the exact before/after** values.

Otherwise you get a nasty UI bug:

> I staged timeout_ms=5000, then I kept editing and now the staged commit includes my later changes too.

**Recommendation:** model staging as “mini-tree overlays”:

* index contains per-selector staged values (or staged patches with from/value)
* commit materializes by applying index onto HEAD (or onto a staged base)

---

### C) Merge base selection: “base” must be an actual LCA

In your worked example, you hand-wave base as the pre-branch commit. In reality, merges need:

* Lowest Common Ancestor (LCA) in the commit DAG
* Handling of criss-cross merges (multiple LCAs)

**Recommendation (MVP):**

* compute one LCA (best effort) and document limitations
* if multiple LCAs, choose one deterministically and warn (or block merges on protected branches)

---

### D) Identity rules: edges need stable IDs, not just (from,to,key)

(from,to,edge_key) works until:

* you allow parallel edges with same key
* you allow edge “conditions” that make edges distinct
* you allow UI rerouting where endpoints stay same but semantics change

**Recommendation:** give edges a stable edge_id (ULID/UUID) like nodes.
You can still canonicalize by (from,to,edge_key,edge_id).

---

### E) Schema migrations are not optional

You mention schema version mismatch conflicts, but you’ll need a policy:

* does fv switch auto-migrate working graphs?
* do commits store graphs in “writer schema” or “repo schema”?
* does merge happen on a normalized schema version?

**Recommendation (MVP):**

* repo has a **declared schema version**
* clients must migrate working state to repo schema before commit
* server rejects commits in the wrong schema version (with a “needs migration” error)

---

## Command surface tweaks (small changes, big UX payoff)

### 1) Add fv restore (or fv checkout -- <selectors>)

Users need “throw away changes to just this node/field” constantly.

Examples:

bash
fv restore node:n42
fv restore field:n42./config/timeout_ms
fv restore --staged node:n42

### 2) Add fv unstage

If you have staging, you need undo for staging.

bash
fv unstage --all
fv unstage node:n42

### 3) Consider one verb: switch (drop checkout)

Git had historical baggage. You don’t need to inherit it.

### 4) Add client-supplied idempotency for commit (important)

You correctly say commit isn’t idempotent, but network retries are real.

**Recommendation:** allow:

* fv commit -m "..." --client_nonce <uuid>
  Server returns the same commit if the nonce repeats (within some window), or returns “already committed.”

This prevents “double commits” after flaky pushes.

---

## Conflict object taxonomy: expand now to avoid later breaking changes

Your conflict object is a great start. I’d add:

### 1) A type and reason

Examples:

* FIELD_BOTH_MODIFIED_DIFFERENTLY
* DELETE_MODIFY
* TYPE_CHANGE_CONFLICT
* SCHEMA_MIGRATION_REQUIRED
* EDGE_REWIRE_CONFLICT

### 2) A machine-checkable “resolution constraints”

So the resolver UI/CLI knows what’s allowed.

json
{
  "allowed_resolutions": ["take_ours", "take_theirs", "manual_edit"],
  "manual_edit_schema": { /* json schema for the field */ }
}

### 3) “Impact hints” (optional but powerful)

Not AI—just graph analysis:

* downstream nodes affected
* triggers affected
* environments impacted

This makes conflict resolution less like defusing a bomb blindfolded.

---

## Diff engine: make “rename/move” a deliberate v2 feature (but prepare for it)

For nodes, rename is just a field change (label).
For workflows (top-level units), “rename workflow” can be:

* a delete + add, or
* a rename op

**Recommendation (MVP):** treat workflow rename as delete+add, but:

* preserve workflow_id stable identity so it *isn’t* really a rename
* display label changes as rename in UI even if internal is “field modified”

That gives you user-friendly semantics without needing fuzzy detection.

---

## Remote push/pull protocol: minimum viable, still correct

You mention “pack-like bundles or API-based.” Either works. The core correctness constraints:

### Server must enforce:

* ref update rules (fast-forward only on protected refs unless merge commit via CR)
* permissions per ref/environment
* object immutability: commit/tree/blob objects never mutate

### Client push should do:

1. GET /refs to learn remote heads
2. compute missing objects reachable from local ref and not on remote
3. POST /objects/batch upload commits/trees/blobs (content-addressed)
4. POST /refs/update with expected old head (CAS: compare-and-swap)

That last step prevents race conditions:

* if remote head changed, reject with FV409_REMOTE_DIVERGED

---

## Performance notes (10k-node graphs without setting your laptop on fire)

### 1) Diff/merge should operate on maps, not lists

Canonical representation should allow:

* nodes_by_id: Map[node_id → node]
* edges_by_id: Map[edge_id → edge]

Then:

* additions/removals are set operations
* modifications are field diffs only for matched IDs

### 2) Hash per node (and maybe per edge)

Instead of hashing only the full tree:

* compute node_hash = sha256(canonical_node_bytes)
* tree hash aggregates node hashes

This enables:

* fast “did node change?” checks
* quick partial diff rendering
* possible future partial fetch/sparse operations

### 3) Avoid O(N²) conflict detection

Conflicts should be detected by intersecting:

* “paths modified in ours” ∩ “paths modified in theirs”

If you track modifications as a set of JSON Pointers per node, conflict detection stays cheap.

---

## Security/audit tightening (two important additions)

### 1) Secret scanning as a pre-commit check (even if you “store references only”)

People will paste keys into “description” fields, test fixtures, etc. Accidents happen.

**Recommendation:** add a required check:

* detect high-entropy strings / known token patterns
* block commit with FV400_SECRET_DETECTED (or warn on non-protected branches, block on protected)

### 2) Audit log should be append-only and queryable by selector

You already want “who changed what.” Make it cheap:

* store changeset summaries indexed by workflow_id, node_id, field_path
* now “show me all changes to /config/retry_policy in prod workflows” is feasible

---

## MVP acceptance criteria (so “done” is falsifiable)

Here are crisp “it works or it doesn’t” tests aligned to your spec:

1. **Staging freeze**

* Modify timeout_ms to 3000, stage it
* Modify again to 5000 (unstaged)
* Commit → commit contains 3000, working tree remains 5000

2. **3-way merge correctness**

* If theirs == base → merge result == ours (no conflicts)
* If both modify disjoint fields → merges cleanly

3. **Conflict determinism**

* Same field modified differently → exactly one conflict object, stable conflict_id across retries

4. **Protected ref enforcement**

* Direct push to main fails with FV423_PROTECTED_REF unless through CR with approvals/checks

5. **Offline commits + later push**

* Create commits locally without remote access
* Later push uploads missing objects, then updates ref with CAS

6. **Canonical hash stability**

* Reordering node JSON keys or node list order does not change tree_id

---

## One “boring but critical” naming suggestion

If you want this to feel native, consider making the nouns consistent across UI/API:

* “repo” vs “workspace” vs “project” tends to create confusion.
* Pick two levels max:

  * **Repo** (container)
  * **Workflow** (top-level artifact)

Everything else is a selector.

---

If you implement just the bolded clarifications—**staging freeze**, **explicit canonicalization rules**, **edge IDs**, and **CAS ref updates**—you’ll avoid ~80% of the painful failure modes that show up only after teams start collaborating for real.

## Response:
Thought for 10m 45s

High-level verdict
------------------

Your review is correct: the spec is already pointed in the right direction, and the failure modes you called out are the ones that actually draw blood in production.

The biggest “will bite” items are:

*   **Canonicalization ambiguity** (layout fields + array semantics)
*   **Staging not freezing values** (classic UI/graph foot-gun)
*   **Edge identity without stable IDs**
*   **Merge base correctness** (LCA + criss-cross)
*   **Schema version/migration policy**
*   **Remote ref update without CAS** (race-condition city)

Below is a concrete “fv spec patch” that tightens those areas without ballooning the MVP.

* * *

fv Spec Patch v0.2 (tighten-now changes)
========================================

1) Canonicalization: define semantic equality as policy, not a vibe
-------------------------------------------------------------------

### 1.1 Two-track model (recommended)

Introduce **two explicit tracks** in the artifact model:

*   **Behavioral track**: affects execution semantics (must be reviewed, conflicts matter)
*   **Presentation track**: affects human readability/layout (reviewable, but merge policy differs)

This becomes a first-class concept in **diff, staging, checks, and merge**.

#### Concrete rule

*   Canonical tree is two subtrees:
    *   `tree.behavioral`
    *   `tree.presentation`

#### Default UX

*   `fv diff` shows **behavioral** by default.
*   `fv diff --presentation` shows presentation-only.
*   PR/CR UI shows behavioral expanded; presentation collapsed.

### 1.2 Declare canonicalization rules per collection/field

You need a **Repo Canonicalization Policy** object stored at repo init and versioned (so changes are explicit and auditable):

```json
{
  "canonicalization_policy": {
    "nodes": { "order": "non_semantic", "sort_key": "node_id" },
    "edges": { "order": "non_semantic", "sort_key": ["from", "to", "edge_key", "edge_id"] },
    "ports": { "order": "semantic", "identity": "port_id" },
    "ui": {
      "included": true,
      "track": "presentation",
      "merge_policy": "lww_by_commit_order"
    }
  }
}
```

**Why this matters:** you avoid accidental drift where one client thinks array order matters and another thinks it doesn’t.

### 1.3 “UI layout” decision (explicit)

Pick one and encode it. I’m choosing the split-track path (practical, matches your recommendation):

*   Layout fields (node `x,y`, viewport, routing control points) are **presentation track**.
*   They are **versioned**, but:
    *   not blocking for behavioral correctness checks,
    *   diffs are collapsed by default,
    *   merge policy is deterministic (see §6).

* * *

2) Staging semantics: the index freezes exact values
----------------------------------------------------

### 2.1 Staging is an overlay, not a live view

Define the index as a set of **frozen patches** with exact `from` and `to`:

```json
{
  "index": {
    "base_head": "cmt_01...",
    "entries": [
      {
        "selector": "field:n42./config/timeout_ms",
        "track": "behavioral",
        "op": "replace",
        "from": 2000,
        "to": 5000,
        "from_hash": "sha256:...",
        "to_hash": "sha256:...",
        "staged_at": "2026-01-29T10:02:25-08:00"
      }
    ]
  }
}
```

### 2.2 Commit materialization rule

On `fv commit`, the commit is materialized by:

*   Starting from **the current HEAD tree** (not the live working tree),
*   Applying **index entries** (the frozen overlay) to produce the new tree.

This guarantees your acceptance test:

> stage 3000 → change working to 5000 → commit contains 3000, working remains 5000.

### 2.3 Index drift protection

Because the index references `from` values, you can detect stale staging:

*   If `HEAD` changed since staging and an entry’s `from` doesn’t match the current HEAD field value, return:

`FV409_INDEX_STALE` with a list of stale selectors.

This is the graph equivalent of “patch does not apply cleanly”.

**MVP simplification:** also block `switch/merge/pull` when index is non-empty unless `--force` or the user stashes/commits. That avoids gnarly “index rebasing” problems early.

* * *

3) Merge base selection: LCA is required (and criss-cross is a policy choice)
-----------------------------------------------------------------------------

### 3.1 Base must be LCA in the DAG

Define merge base as:

*   `base = lowest_common_ancestor(ours, theirs)` in commit DAG

### 3.2 Multiple LCAs (criss-cross merges)

Policy (MVP-safe, especially for protected branches):

*   If multiple LCAs:
    *   On **unprotected branches**: choose deterministically (lexicographically smallest commit\_id) and return `FV299_MULTIPLE_LCA_WARNING`
    *   On **protected branches**: block merge with `FV409_MULTIPLE_LCA_BLOCKED`

This keeps protected flows boring (good).

* * *

4) Identity rules: edges get stable IDs
---------------------------------------

### 4.1 Edge schema change (tighten now)

Edges must have `edge_id` (ULID/UUID), full stop:

```json
{
  "edge_id": "e_01J...",
  "from": "n10",
  "to": "n42",
  "edge_key": "success",
  "condition": { /* optional */ }
}
```

### 4.2 Matching rule in diff/merge

*   Match edges by `edge_id`
*   If older data exists without `edge_id`, run a one-time migration that assigns IDs deterministically (hash of canonical edge fields + stable salt).

* * *

5) Schema migrations: a repo-declared schema version and strict enforcement
---------------------------------------------------------------------------

### 5.1 Repo schema version is authoritative

Repo stores:

*   `repo_schema_version` (e.g., `wf_schema@3`)

### 5.2 Client behavior

*   Client **must** migrate working state to `repo_schema_version` before staging/commit.
*   Provide explicit command:

```bash
fv migrate --to repo
```

### 5.3 Server enforcement

*   Server rejects commits whose `schema_version != repo_schema_version`:

`FV412_SCHEMA_MISMATCH` with required version + migration hints.

This prevents “half the team upgraded” merge disasters.

* * *

6) Merge strategy updates with two-track behavior
-------------------------------------------------

### 6.1 Behavioral track

*   True 3-way merge
*   Conflicts are blocking unless resolved

### 6.2 Presentation track (deterministic but non-blocking by default)

Choose one deterministic policy. I recommend:

*   If only one side changed presentation fields for a selector → take that change
*   If both changed the same presentation field differently → **take ours** (or **take theirs**, but pick one)
*   Emit a **non-blocking conflict note** (not a conflict object that blocks merge) unless user sets `--strict-presentation`

This avoids layout edits becoming merge hell while still preserving information.

* * *

7) Command surface tweaks (small but high leverage)
---------------------------------------------------

### 7.1 Add `fv restore`

Restore working or staged for selectors.

```bash
fv restore node:n42
fv restore field:n42./config/timeout_ms
fv restore --staged field:n42./config/timeout_ms
```

Semantics:

*   default: restore working selector to **HEAD**
*   `--staged`: restore index selector to **HEAD** (i.e., remove staged entry / reset to staged base)

### 7.2 Add `fv unstage`

Pure staging undo:

```bash
fv unstage --all
fv unstage node:n42
fv unstage field:n42./config/timeout_ms
```

### 7.3 Single verb: keep `switch`, drop `checkout`

Agree. Don’t inherit Git’s archaeology.

* * *

8) Commit idempotency: client nonce + deterministic commit IDs
--------------------------------------------------------------

Network retries are real, and offline mode complicates “server dedupe”.

### 8.1 Add `--client_nonce`

```bash
fv commit -m "..." --client_nonce 7e2d... 
```

### 8.2 Make commit\_id derivable (optional but clean)

If you want commits to be stable locally/offline, compute:

```
commit_id = sha256(
  parents + tree_id_behavioral + tree_id_presentation +
  author_id + message + client_nonce
)
```

*   `timestamp` becomes metadata (not part of commit\_id), or it is derived deterministically from local clock but excluded from hash.
*   If the same `client_nonce` repeats with identical staged content, you get the same commit\_id.

### 8.3 Server dedupe rule

Server stores `(author_id, client_nonce) -> commit_id` mapping for a time window (or indefinitely), returning the existing commit on retries.

* * *

9) Conflict object taxonomy: expand now to avoid breaking clients later
-----------------------------------------------------------------------

### 9.1 Conflict object schema (v2-compatible)

```json
{
  "conflict_id": "cx_sha256:...",
  "type": "FIELD_BOTH_MODIFIED_DIFFERENTLY",
  "reason": "Same field changed in both branches with different values.",
  "track": "behavioral",
  "selector": "field:n42./config/timeout_ms",
  "base": 2000,
  "ours": 3000,
  "theirs": 5000,
  "severity": "behavioral",
  "allowed_resolutions": ["take_ours", "take_theirs", "manual_edit"],
  "manual_edit_schema": { "type": "integer", "minimum": 0, "maximum": 600000 },
  "impact_hints": {
    "downstream_nodes": ["n11", "n12"],
    "triggers_affected": ["refund_request"],
    "environments": ["staging", "prod"]
  }
}
```

### 9.2 Stable conflict\_id rule (determinism)

Make `conflict_id` a hash of:

*   merge base commit\_id
*   ours commit\_id
*   theirs commit\_id
*   selector
*   conflict type

This guarantees stability across retries and across clients.

* * *

10) Remote push/pull protocol: minimum viable and correct (CAS ref updates)
---------------------------------------------------------------------------

This is the “don’t corrupt history under concurrency” part.

### 10.1 Object model constraints

Server must enforce:

*   object immutability (commits/trees/blobs never mutate)
*   ref updates are atomic and permission-checked
*   protected refs allow only PR-mediated updates (or strict FF rules)

### 10.2 Push algorithm (explicit)

1.  `GET /refs` → learn remote heads
2.  compute missing objects reachable from local ref and not on remote
3.  `POST /objects/batch` → upload objects (content-addressed)
4.  `POST /refs/update` with CAS:

```json
{
  "ref": "refs/heads/main",
  "expected_old": "cmt_01OLD...",
  "new": "cmt_01NEW..."
}
```

If head changed:

*   reject with `FV409_REMOTE_DIVERGED`

This is non-negotiable if you want correctness.

* * *

11) Performance tightening (10k nodes without pain)
---------------------------------------------------

### 11.1 Internal representation: maps, not lists

Canonical in-memory representation:

*   `nodes_by_id: Map[node_id -> node]`
*   `edges_by_id: Map[edge_id -> edge]`

Diff becomes:

*   additions/removals via set difference
*   modifications by comparing hashes

### 11.2 Hash per node/edge

Store:

*   `node_hash`
*   `edge_hash`

Tree hash aggregates these (Merkle-ish). Benefits:

*   fast “did it change?”
*   partial diff rendering
*   future sparse fetch

### 11.3 Conflict detection via path intersection

Track modified paths as:

*   `(node_id, json_pointer)` pairs

Conflict check:

*   intersect modified sets of ours vs theirs

Avoid O(N²) scanning.

* * *

12) Security/audit tightening
-----------------------------

### 12.1 Secret scanning pre-commit (required on protected refs)

Even with “secrets are references,” humans paste keys into descriptions.

Add check:

*   high-entropy detection + known token regexes
*   behavior:
    *   warn on non-protected branches (configurable)
    *   block on protected branches: `FV400_SECRET_DETECTED`

### 12.2 Audit indexed by selector

Store changeset summaries indexed by:

*   workflow\_id
*   node\_id
*   field\_path
*   environment (if deploy metadata exists)

This makes queries cheap and enables real governance.

* * *

MVP acceptance criteria (updated, falsifiable)
==============================================

1.  **Staging freeze**
    *   stage field value A
*   change working to B
*   commit contains A; working remains B
    2.  **3-way merge correctness**
    *   theirs == base ⇒ result == ours (no conflicts)
*   disjoint field changes ⇒ clean merge
    3.  **Conflict determinism**
    *   same selector modified differently ⇒ one conflict
*   same merge inputs ⇒ identical `conflict_id`
    4.  **Protected ref enforcement**
    *   direct push to `main` rejected (`FV423_PROTECTED_REF`)
*   PR merge allowed only with approvals + checks
    5.  **Offline commits + later push**
    *   local commits created offline
*   later `push` uploads missing objects then CAS-updates refs
    6.  **Canonical hash stability**
    *   reorder keys and node/edge lists ⇒ `tree_id_behavioral` unchanged
*   presentation-only edits change `tree_id_presentation` but not behavioral

* * *

What will still bite (even after these fixes) — and how to contain it
=====================================================================

“Presentation merge policy resentment”
--------------------------------------

Someone will dislike “ours wins” (or “theirs wins”) for layout. That’s fine if:

*   it’s documented,
*   it’s deterministic,
*   UI shows “presentation auto-merged” notes,
*   `--strict-presentation` exists for teams who care.

Schema migration cadence
------------------------

You’ll want:

*   server-side “minimum client version” gating eventually,
*   a migration test suite (fixtures across versions),
*   a rule that PR checks run on migrated canonical form.

* * *

The one change I’d emphasize hardest
====================================

If you do only four tightenings from your review, make them these (in this exact order):

1.  **Index freezes exact values** (staging overlay with from/to)
2.  **Explicit canonicalization policy + behavioral/presentation split**
3.  **Stable `edge_id`**
4.  **CAS ref updates on push**

That combination prevents the majority of “collaboration-induced insanity” without turning fv into a research project.

Next logical step is to write the **normative schemas** (JSON Schema / protobuf) for:

*   canonical workflow
*   index entries
*   changeset format
*   conflict objects
*   ref update requests

…because once those stabilize, the rest of the system becomes engineering rather than mythology.

## Prompt:
## This v0.2 patch is the right kind of boring

You tightened exactly the spots where “graphs + collaboration” tends to become a haunted house: canonicalization, staging freeze, IDs, LCA, schema policy, and CAS. This is the difference between a pleasant tool and a system that spawns folklore.

What’s left now is mostly *spec hygiene*: make a few remaining “implicit choices” explicit so implementations don’t diverge.

---

## The remaining sharp edges to file down

### 1) Canonicalization policy: where it lives, how it versions, and whether it affects hashes

You introduced a canonicalization_policy object (✅), but the spec still needs to say:

* Is this policy stored in **repo config** (out-of-tree metadata), or **in the versioned tree**?
* If it changes, does it:

  * require a repo migration, or
  * simply apply going forward?

**Why it matters:** if two clients apply different canonicalization, they compute different tree_id_* for the “same” logical content.

**MVP-safe recommendation:**

* Treat canonicalization_policy as part of the **repo schema contract**.
* Store it in repo config with a policy_version and a policy_hash.
* Require client_policy_hash == repo_policy_hash for commit/push (same enforcement style as schema version).

Add to server enforcement:

* FV412_POLICY_MISMATCH (parallel to schema mismatch)

And add to commit header:

json
"policy_hash": "sha256:..."

You do *not* need to include it in tree_id_* if you enforce it strictly, but including it in the commit header makes audits clearer.

---

### 2) Track boundaries: define them as a mapping, not prose

You’ve got the two-track split (behavioral vs presentation). Now you need one more piece:

* A **field-to-track mapping** that is machine-readable.

Otherwise, different clients will disagree on whether a field is behavioral or presentation, and you’ll get “why did this fail checks?” arguments.

**Minimal approach:**

* Extend canonicalization policy with explicit path rules:

json
"track_rules": [
  { "match": "/nodes/*/config/**", "track": "behavioral" },
  { "match": "/nodes/*/ui/**",     "track": "presentation" },
  { "match": "/edges/*/condition/**", "track": "behavioral" },
  { "match": "/edges/*/ui/**",        "track": "presentation" }
]

(Use whatever glob/JSON-pointer pattern system you like—just don’t leave it implicit.)

---

### 3) Staging: selector → patch expansion rules (very important for UX)

You’ve defined staging as frozen patches (✅). What’s still ambiguous:

* If I run fv add node:n42, does that stage:

  * behavioral only,
  * presentation only,
  * or both tracks?

Git stages “the file,” not “some parts,” unless you hunk-stage. Here you need a default.

**MVP recommendation:**

* fv add node:<id> stages **behavioral track by default**.
* Add --track presentation|behavioral|both to add, diff, and restore.

Examples:

bash
fv add node:n42                 # behavioral default
fv add node:n42 --track both
fv diff --track presentation
fv restore node:n42 --track presentation

This keeps your “behavioral first” posture consistent everywhere.

---

### 4) Presentation merge policy: avoid “commit order” as a tie-breaker

You wrote lww_by_commit_order in policy, and later described “take ours” on presentation conflicts. Those aren’t the same thing, and “commit order” is slippery in a DAG.

**Make this deterministic and boring:**

* Pick one default and name it explicitly:

  * prefer_ours
  * prefer_theirs
  * union_where_possible_else_prefer_ours
* Treat --strict-presentation as “promote presentation conflicts into blocking conflicts.”

Also: when you “prefer ours,” still emit a **merge note** with a stable ID so UIs can surface “layout changed on both sides; we picked ours.”

Example note object:

json
{
  "note_id": "nx_sha256:...",
  "track": "presentation",
  "selector": "field:n42./ui/pos",
  "type": "PRESENTATION_DIVERGED_AUTO_RESOLVED",
  "resolution": "prefer_ours"
}

This avoids polluting the *blocking conflict* channel while still preserving accountability.

---

### 5) Edge migration: deterministic assignment must handle duplicates

You propose a one-time migration assigning edge_id deterministically from canonical edge fields + salt. That works **unless** legacy data has parallel edges with identical (from,to,edge_key,condition).

**Patch the migration algorithm with a collision rule:**

* Sort legacy edges canonically.
* For each edge, compute a base hash.
* If collision, append a deterministic suffix counter.

Pseudo:

* edge_id = "e_" + sha256(edge_canonical_bytes + repo_salt + "#" + occurrence_index)

Also: once assigned, edge_id becomes **persisted state**, not recomputed.

---

### 6) Commit ID determinism vs immutability: pick what you want to be content-addressed

You suggest making commit_id derivable and excluding timestamp. That’s workable, but you should be explicit about what is immutable / tamper-evident:

* If commit_id doesn’t hash the full commit object, then the server *could* mutate commit metadata without changing commit_id unless signatures are mandatory.

**Two clean MVP options:**

**Option A (simplest, common):**

* commit_id = sha256(full_commit_object_bytes) (includes authored_at)
* Idempotency is handled by (author_id, client_nonce) -> commit_id mapping
* Offline “same staged content” does *not* guarantee same commit_id, and that’s fine

**Option B (your direction, more subtle):**

* commit_id hashes parents + tree roots + author_id + message + nonce (no timestamp)
* Require server to store server_received_at in the audit log (append-only), not in the commit
* Strongly recommend signing if you care about tamper evidence of metadata

If you keep B, add an explicit rule:

* **Nonce reuse with different content is an error**

  * FV409_NONCE_REUSE_MISMATCH

Otherwise retries can accidentally “dedupe” the wrong commit.

---

### 7) CAS ref updates: specify branch creation and deletion

Your CAS write is correct. Add just two more cases so implementers don’t invent them differently:

* Creating a new ref:

  * expected_old = null
* Deleting a ref:

  * new = null and expected_old = <current_head>

Example:

json
{ "ref": "refs/heads/feature/x", "expected_old": null, "new": "cmt_01..." }
{ "ref": "refs/heads/feature/x", "expected_old": "cmt_01...", "new": null }

---

## A small “v0.2.1” patch list (tight, MVP-friendly)

If you want a minimal follow-on patch that eliminates the last ambiguity, it’s basically:

1. Add policy_hash + FV412_POLICY_MISMATCH enforcement
2. Add machine-readable track_rules
3. Add --track flag to add/diff/restore + defaults (node stages behavioral)
4. Replace lww_by_commit_order with prefer_ours|prefer_theirs + optional strict mode
5. Define edge migration collision handling
6. Define nonce reuse mismatch error
7. Define CAS semantics for create/delete refs
8. Add non-blocking merge_notes[] for presentation auto-resolutions

That’s it. No ballooning.

---

## Concrete schemas (skeletons you can drop into a repo today)

Below are intentionally compact JSON Schema skeletons to lock down interoperability. They aren’t exhaustive; they’re meant to freeze the *shape* and the “must-not-diverge” semantics.

### Commit object (skeleton)

json
{
  "$id": "https://flowversion.dev/schemas/commit.json",
  "type": "object",
  "required": ["commit_id", "parents", "author", "message", "tree", "policy_hash", "schema_version"],
  "properties": {
    "commit_id": { "type": "string" },
    "parents": { "type": "array", "items": { "type": "string" } },
    "author": {
      "type": "object",
      "required": ["user_id", "display_name"],
      "properties": {
        "user_id": { "type": "string" },
        "display_name": { "type": "string" }
      }
    },
    "message": { "type": "string" },
    "client_nonce": { "type": "string" },
    "authored_at": { "type": "string", "format": "date-time" },

    "schema_version": { "type": "string" },
    "policy_hash": { "type": "string" },

    "tree": {
      "type": "object",
      "required": ["behavioral_tree_id", "presentation_tree_id"],
      "properties": {
        "behavioral_tree_id": { "type": "string" },
        "presentation_tree_id": { "type": "string" }
      }
    },

    "signatures": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["alg", "public_key_id", "sig"],
        "properties": {
          "alg": { "type": "string", "enum": ["ed25519"] },
          "public_key_id": { "type": "string" },
          "sig": { "type": "string" }
        }
      }
    }
  }
}

### Index entry (frozen patch)

json
{
  "$id": "https://flowversion.dev/schemas/index_entry.json",
  "type": "object",
  "required": ["selector", "track", "op", "from_hash", "to_hash", "staged_at"],
  "properties": {
    "selector": { "type": "string" },
    "track": { "type": "string", "enum": ["behavioral", "presentation"] },
    "op": { "type": "string", "enum": ["add", "remove", "replace", "move", "copy", "test"] },
    "path": { "type": "string" },
    "from": {},
    "to": {},
    "from_hash": { "type": "string" },
    "to_hash": { "type": "string" },
    "staged_at": { "type": "string", "format": "date-time" }
  }
}

### Conflict object (blocking)

json
{
  "$id": "https://flowversion.dev/schemas/conflict.json",
  "type": "object",
  "required": ["conflict_id", "type", "track", "selector", "allowed_resolutions"],
  "properties": {
    "conflict_id": { "type": "string" },
    "type": { "type": "string" },
    "reason": { "type": "string" },
    "track": { "type": "string", "enum": ["behavioral"] },
    "selector": { "type": "string" },
    "base": {},
    "ours": {},
    "theirs": {},
    "severity": { "type": "string" },
    "allowed_resolutions": {
      "type": "array",
      "items": { "type": "string", "enum": ["take_ours", "take_theirs", "manual_edit"] }
    },
    "manual_edit_schema": { "type": "object" },
    "impact_hints": { "type": "object" }
  }
}

### Merge note (non-blocking; presentation)

json
{
  "$id": "https://flowversion.dev/schemas/merge_note.json",
  "type": "object",
  "required": ["note_id", "track", "selector", "type", "resolution"],
  "properties": {
    "note_id": { "type": "string" },
    "track": { "type": "string", "enum": ["presentation"] },
    "selector": { "type": "string" },
    "type": { "type": "string" },
    "resolution": { "type": "string", "enum": ["prefer_ours", "prefer_theirs"] }
  }
}

### CAS ref update request

json
{
  "$id": "https://flowversion.dev/schemas/ref_update.json",
  "type": "object",
  "required": ["ref", "expected_old"],
  "properties": {
    "ref": { "type": "string" },
    "expected_old": { "type": ["string", "null"] },
    "new": { "type": ["string", "null"] }
  }
}

---

## Bottom line

Your v0.2 patch fixes the blood-drawing failures. The “next correctness step” is not new features; it’s **closing ambiguity**:

* policy hash enforcement
* track rule mapping
* track defaults for staging
* deterministic presentation merge policy
* edge migration collision rules
* explicit CAS create/delete semantics
* nonce reuse mismatch rule

Once those are nailed down, implementations stop diverging, and fv becomes engineering instead of interpretive dance.

## Response:
Thought for 15m 21s

v0.2.1 patch (spec hygiene): make the remaining implicit choices explicit
-------------------------------------------------------------------------

You’re pointing at exactly the last places where “two correct implementations” can still diverge and quietly fork reality. Here’s a tight **v0.2.1** patch that locks down interoperability without expanding scope.

* * *

0) v0.2.1 change list (normative)
=================================

1.  **Canonicalization policy becomes a repo-enforced contract**
    *   Stored in repo config with `policy_version` + `policy_hash`
    *   Commit header includes `policy_hash`
    *   Server enforces `FV412_POLICY_MISMATCH`
2.  **Tracks become machine-defined**
    *   Add `track_rules[]` to policy (path → track mapping, with defined precedence)
3.  **Staging selector expansion becomes explicit**
    *   `fv add` stages **behavioral by default** for `node:`/`wf:`/`--all`
    *   Add `--track behavioral|presentation|both` to `add/diff/restore/unstage`
    *   `field:` selectors infer track; explicit mismatch is an error
4.  **Presentation merge policy becomes deterministic and named**
    *   Replace `lww_by_commit_order` with `prefer_ours|prefer_theirs|union_else_prefer_ours`
    *   Add `--strict-presentation` to promote presentation divergences into blocking conflicts
    *   Add **non-blocking `merge_notes[]`** for auto-resolutions
5.  **Edge migration collision handling is specified**
    *   Deterministic edge\_id assignment includes occurrence index to avoid collisions
6.  **Commit idempotency semantics are hardened**
    *   `client_nonce` dedupe + `FV409_NONCE_REUSE_MISMATCH` if reused with different content
7.  **CAS ref updates define create/delete**
    *   `expected_old = null` for create
    *   `new = null` for delete

* * *

1) Canonicalization policy: where it lives, how it versions, and what hashes it affects
=======================================================================================

1.1 Storage location (explicit)
-------------------------------

**Canonicalization policy lives in repo config (out-of-tree metadata), not in the versioned tree.**

*   Remote: `RepoConfig.canonicalization_policy`
*   Local clone: `.fv/policy.json` (cached copy)
*   Policy changes are **admin-only** operations.

Rationale: policy is part of the _protocol contract_ needed to compute identical canonical bytes/hashes across clients.

1.2 Versioning + enforcement (explicit)
---------------------------------------

Repo config includes:

*   `policy_version` (monotonic integer)
*   `policy_hash = sha256(canonical_policy_bytes)`

**Server enforcement rules**

*   For `commit` (and `push` containing commits):
    *   if `commit.policy_hash != repo.policy_hash` ⇒ reject with `FV412_POLICY_MISMATCH`
*   For `merge`:
    *   if `base/ours/theirs` don’t share the same `policy_hash` ⇒ reject with `FV412_POLICY_MISMATCH` (details in response)

**Error**

*   `FV412_POLICY_MISMATCH`: “Client policy does not match repo policy.”

1.3 Does policy affect `tree_id_*`?
-----------------------------------

*   The policy **does not get concatenated into `tree_id_*` directly**.
*   But policy **does affect canonicalization**, therefore it **implicitly affects tree bytes**, therefore it **implicitly affects `tree_id_*`**.

To keep audits readable:

*   `policy_hash` is included in the **commit header** (and therefore in the commit hash if you use full-object hashing; see §6).

1.4 What happens if the policy changes?
---------------------------------------

Make this explicit as an operational rule. Two MVP-safe options:

### Option 1 (MVP default): policy is immutable after `init`

*   No policy updates in MVP.
*   If you really need a new policy, you create a new repo (or upgrade in v2).

✅ Simplest; zero mixed-policy edge cases.

### Option 2 (v2 migration): policy updates are allowed but require normalization

*   Admin sets new `policy_version` + `policy_hash`
*   New commits must use the new policy
*   **Merge is only allowed among commits sharing the same policy\_hash**
*   A migration tool creates a **policy-normalization commit** on any branch head you want to keep collaborating on:
    *   semantics unchanged
    *   canonical representation rewritten under the new policy

✅ Flexible; more moving parts.

**Spec decision for v0.2.1:** adopt **Option 1 for MVP**, define Option 2 as v2 behavior.

* * *

2) Track boundaries: make them a mapping, not prose
===================================================

2.1 Machine-readable `track_rules`
----------------------------------

Add `track_rules[]` to policy. Rules are evaluated against **canonical JSON Pointer paths** (see §3.1).

Example:

```json
"track_rules": [
  { "match": "/nodes/*/config/**",        "track": "behavioral" },
  { "match": "/nodes/*/ui/**",            "track": "presentation" },
  { "match": "/edges/*/condition/**",     "track": "behavioral" },
  { "match": "/edges/*/ui/**",            "track": "presentation" },
  { "match": "/viewport/**",              "track": "presentation" }
],
"default_track": "behavioral"
```

2.2 Pattern semantics (explicit)
--------------------------------

*   `*` matches exactly one path segment
*   `**` matches zero or more segments
*   Paths are JSON Pointer-like (`/a/b/c`), applied **relative to a workflow root** (see §3.1)

2.3 Rule precedence (explicit, deterministic)
---------------------------------------------

*   Rules are evaluated in order
*   **Last match wins**
*   If no rules match, use `default_track`

This gives you a clean “override” story.

* * *

3) Staging: selector → patch expansion rules + `--track` defaults
=================================================================

3.1 Canonical tree shape (so paths are stable)
----------------------------------------------

To make patches and track rules unambiguous, define canonical workflow structure as **maps keyed by stable IDs**:

**Behavioral root (per workflow):**

*   `/nodes/<node_id>/...` (behavioral fields)
*   `/edges/<edge_id>/...` (behavioral fields)

**Presentation root (per workflow):**

*   `/nodes/<node_id>/ui/...`
*   `/edges/<edge_id>/ui/...`
*   `/viewport/...`

(You can wrap this under `/workflows/<workflow_id>/...` at the repo tree level; track rules are evaluated relative to the workflow root.)

3.2 `fv add` expansion algorithm (normative)
--------------------------------------------

When the user runs `fv add <selector> [--track T]`, the system MUST:

1.  Determine target scope (workflow/node/field/edge)
2.  Determine track set `T`:
    *   default rules in §3.3
3.  Compute `delta = diff(HEAD, WORKING)` restricted to the selected scope AND track set
4.  Normalize `delta` into a stable list of JSON Patch ops (sorted deterministically)
5.  For each op, create an **index entry** capturing exact before/after and hashes

Index entries are frozen: later working changes do not mutate staged content.

3.3 Track defaults + `--track` behavior (explicit)
--------------------------------------------------

### Defaults

*   `fv add node:<id>` stages **behavioral** by default
*   `fv add wf:<id>` stages **behavioral** by default
*   `fv add --all` stages **behavioral** by default
*   `fv diff` shows **behavioral** by default
*   `fv restore` operates on **behavioral** by default for node/workflow/all selectors

### Flag

Add to commands:

*   `fv add … --track behavioral|presentation|both`
*   `fv diff … --track behavioral|presentation|both`
*   `fv restore … --track behavioral|presentation|both`
*   `fv unstage … --track behavioral|presentation|both`

### Field selectors (important constraint)

For `field:` selectors:

*   Track is **inferred** by `track_rules` for that field’s canonical path
*   If user supplies `--track` and it **does not match inferred track**, return:
    *   `FV400_TRACK_MISMATCH`

This prevents “reclassify a behavioral field as presentation” chaos.

* * *

4) Presentation merge policy: deterministic, named, and auditable
=================================================================

4.1 Replace `lww_by_commit_order` with explicit policy enum
-----------------------------------------------------------

Add to policy:

*   `presentation_merge_policy` ∈
    *   `prefer_ours` (MVP default)
    *   `prefer_theirs`
    *   `union_else_prefer_ours` (safe-ish when representation supports union)

**MVP decision:** default `prefer_ours`.

4.2 Strict mode
---------------

Add merge flag:

```bash
fv merge <branch> --strict-presentation
```

Behavior:

*   Presentation divergences become **blocking conflicts** (same conflict object channel)
*   Without strict mode, presentation divergences produce **merge notes** only

4.3 Merge notes (non-blocking channel)
--------------------------------------

Merge result includes:

```json
"merge_notes": [
  {
    "note_id": "nx_sha256:...",
    "track": "presentation",
    "selector": "field:n42./ui/pos",
    "type": "PRESENTATION_DIVERGED_AUTO_RESOLVED",
    "resolution": "prefer_ours"
  }
]
```

**Stable `note_id` rule (determinism):**  
`note_id = sha256(base_commit_id + ours_commit_id + theirs_commit_id + selector + type)`

* * *

5) Edge migration: deterministic assignment with collision handling
===================================================================

5.1 Migration scope
-------------------

Only for legacy data missing `edge_id`.

5.2 Deterministic algorithm (normative)
---------------------------------------

Given:

*   `repo_salt` (random, stored in repo config; stable forever)
*   legacy edges list per workflow

Procedure:

1.  Canonically sort legacy edges by `(from, to, edge_key, canonical(condition), canonical(ui))`
2.  For each edge in sorted order:
    *   compute `base = sha256(canonical_edge_bytes + repo_salt)`
3.  If `base` collides (same hash seen before in this workflow):
    *   assign `edge_id = "e_" + sha256(canonical_edge_bytes + repo_salt + "#" + occurrence_index)`
    *   where `occurrence_index` is 0-based among identical `base`
4.  Persist assigned `edge_id` into the canonical state (it becomes stored state, not recomputed)

This handles true duplicates deterministically.

* * *

6) Commit ID determinism vs immutability: pick the boring invariant
===================================================================

You laid out the key subtlety correctly: if `commit_id` doesn’t hash the full commit object, metadata tamper-evidence gets weird unless signatures are mandatory.

v0.2.1 decision (MVP): Option A
-------------------------------

**Commit IDs are content-addressed over the full canonical commit object.**

*   `commit_id = sha256(canonical_commit_object_bytes)`
*   Canonical commit bytes include:
    *   parents
    *   author
    *   message
    *   `client_nonce` (if present)
    *   `authored_at`
    *   `schema_version`
    *   `policy_hash`
    *   tree root IDs
    *   optional `merge_notes` (for merge commits)
    *   (signatures are excluded from the hash input; they sign the commit\_id)

**Idempotency**

*   If `client_nonce` provided:
    *   server stores `(author_id, client_nonce) -> commit_id`
    *   retries return the same commit
*   If the same nonce is reused with different content:
    *   reject with `FV409_NONCE_REUSE_MISMATCH`

This gives you:

*   strong immutability / tamper evidence
*   retry safety
*   no “DAG order” weirdness

* * *

7) CAS ref updates: define create/delete explicitly
===================================================

7.1 Semantics
-------------

Ref update is a CAS operation:

*   Create:
    *   `expected_old = null`
    *   `new = <commit_id>`
*   Update:
    *   `expected_old = <current_head>`
    *   `new = <commit_id>`
*   Delete:
    *   `expected_old = <current_head>`
    *   `new = null`

7.2 Required server behavior
----------------------------

*   If `expected_old` does not match current server value:
    *   reject with `FV409_REMOTE_DIVERGED`
*   Protected refs:
    *   reject direct updates with `FV423_PROTECTED_REF` unless performed by CR merge path

* * *

8) Schema skeletons (v0.2.1) — compact but interoperability-safe
================================================================

These are “shape locks”: they freeze the fields that MUST NOT diverge across implementations.

8.1 Repo config (new)
---------------------

```json
{
  "$id": "https://flowversion.dev/schemas/repo_config.json",
  "type": "object",
  "required": ["repo_id", "schema_version", "canonicalization_policy"],
  "properties": {
    "repo_id": { "type": "string" },
    "schema_version": { "type": "string" },

    "canonicalization_policy": {
      "$ref": "https://flowversion.dev/schemas/canonicalization_policy.json"
    },

    "repo_salt": { "type": "string" }
  }
}
```

8.2 Canonicalization policy (new)
---------------------------------

```json
{
  "$id": "https://flowversion.dev/schemas/canonicalization_policy.json",
  "type": "object",
  "required": [
    "policy_version",
    "policy_hash",
    "track_rules",
    "default_track",
    "presentation_merge_policy"
  ],
  "properties": {
    "policy_version": { "type": "integer", "minimum": 1 },
    "policy_hash": { "type": "string" },

    "track_rules": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["match", "track"],
        "properties": {
          "match": { "type": "string" },
          "track": { "type": "string", "enum": ["behavioral", "presentation"] }
        }
      }
    },

    "default_track": { "type": "string", "enum": ["behavioral", "presentation"] },

    "presentation_merge_policy": {
      "type": "string",
      "enum": ["prefer_ours", "prefer_theirs", "union_else_prefer_ours"]
    },

    "canonical_sort": {
      "type": "object",
      "properties": {
        "nodes_sort_key": { "type": "string", "enum": ["node_id"] },
        "edges_sort_key": {
          "type": "array",
          "items": { "type": "string", "enum": ["from", "to", "edge_key", "edge_id"] }
        }
      }
    }
  }
}
```

8.3 Commit object (revised)
---------------------------

```json
{
  "$id": "https://flowversion.dev/schemas/commit.json",
  "type": "object",
  "required": [
    "commit_id",
    "parents",
    "author",
    "message",
    "tree",
    "policy_hash",
    "schema_version",
    "authored_at"
  ],
  "properties": {
    "commit_id": { "type": "string" },
    "parents": { "type": "array", "items": { "type": "string" } },

    "author": {
      "type": "object",
      "required": ["user_id", "display_name"],
      "properties": {
        "user_id": { "type": "string" },
        "display_name": { "type": "string" }
      }
    },

    "message": { "type": "string" },
    "client_nonce": { "type": "string" },
    "authored_at": { "type": "string", "format": "date-time" },

    "schema_version": { "type": "string" },
    "policy_hash": { "type": "string" },

    "tree": {
      "type": "object",
      "required": ["behavioral_tree_id", "presentation_tree_id"],
      "properties": {
        "behavioral_tree_id": { "type": "string" },
        "presentation_tree_id": { "type": "string" }
      }
    },

    "merge_notes": {
      "type": "array",
      "items": { "$ref": "https://flowversion.dev/schemas/merge_note.json" }
    },

    "signatures": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["alg", "public_key_id", "sig"],
        "properties": {
          "alg": { "type": "string", "enum": ["ed25519"] },
          "public_key_id": { "type": "string" },
          "sig": { "type": "string" }
        }
      }
    }
  }
}
```

8.4 Index entry (frozen patch) (revised)
----------------------------------------

```json
{
  "$id": "https://flowversion.dev/schemas/index_entry.json",
  "type": "object",
  "required": ["selector", "track", "op", "path", "from_hash", "to_hash", "staged_at"],
  "properties": {
    "selector": { "type": "string" },
    "track": { "type": "string", "enum": ["behavioral", "presentation"] },

    "op": { "type": "string", "enum": ["add", "remove", "replace", "move", "copy", "test"] },
    "path": { "type": "string" },

    "from": {},
    "to": {},

    "from_hash": { "type": "string" },
    "to_hash": { "type": "string" },

    "staged_at": { "type": "string", "format": "date-time" }
  }
}
```

8.5 Conflict object (blocking) (unchanged intent; tightened type)
-----------------------------------------------------------------

```json
{
  "$id": "https://flowversion.dev/schemas/conflict.json",
  "type": "object",
  "required": ["conflict_id", "type", "track", "selector", "allowed_resolutions"],
  "properties": {
    "conflict_id": { "type": "string" },
    "type": { "type": "string" },
    "reason": { "type": "string" },

    "track": { "type": "string", "enum": ["behavioral"] },

    "selector": { "type": "string" },
    "base": {},
    "ours": {},
    "theirs": {},

    "severity": { "type": "string" },

    "allowed_resolutions": {
      "type": "array",
      "items": { "type": "string", "enum": ["take_ours", "take_theirs", "manual_edit"] }
    },

    "manual_edit_schema": { "type": "object" },
    "impact_hints": { "type": "object" }
  }
}
```

8.6 Merge note (non-blocking; presentation) (as you proposed)
-------------------------------------------------------------

```json
{
  "$id": "https://flowversion.dev/schemas/merge_note.json",
  "type": "object",
  "required": ["note_id", "track", "selector", "type", "resolution"],
  "properties": {
    "note_id": { "type": "string" },
    "track": { "type": "string", "enum": ["presentation"] },
    "selector": { "type": "string" },
    "type": { "type": "string" },
    "resolution": { "type": "string", "enum": ["prefer_ours", "prefer_theirs"] }
  }
}
```

8.7 CAS ref update request (revised to require `new`)
-----------------------------------------------------

```json
{
  "$id": "https://flowversion.dev/schemas/ref_update.json",
  "type": "object",
  "required": ["ref", "expected_old", "new"],
  "properties": {
    "ref": { "type": "string" },
    "expected_old": { "type": ["string", "null"] },
    "new": { "type": ["string", "null"] }
  }
}
```

* * *

What this buys you (practically)
================================

*   **No divergent hashing** due to policy drift (policy\_hash gate)
*   **No track arguments** caused by implicit field classification (track\_rules)
*   **No “staging is haunted” bugs** (selector expansion → frozen patches)
*   **No nondeterministic layout merges** (named policy + merge\_notes)
*   **No legacy edge ambiguity** (collision-safe migration)
*   **No duplicate commits on flaky networks** (nonce mapping + mismatch error)
*   **No races on refs** (CAS create/update/delete semantics)

At this point, fv stops being “a clever spec” and becomes an implementable protocol with the right kind of boredom: the kind you can scale without inventing tribal rituals.

If you want the next tight step after v0.2.1, it’s not more features—it’s defining the **canonical workflow JSON** itself (the exact field sets per track and the per-node/edge hashing rules), because that’s the final source of interoperability truth.

