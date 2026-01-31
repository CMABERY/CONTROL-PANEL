# Domain-Native Version Control Kit

This document is the “glue layer” that turns three complementary docs into a single, implementable kit:

- **C — Design Space Analysis**: mental model + design levers (what makes it feel native).
- **B — Git in Minecraft Analysis**: architecture boundary + correctness invariants (what prevents betrayal).
- **A — Version Control Design Template**: spec generator for “GitHub-for-X” (how you ship it).

It is **normative**: where it says MUST/SHOULD/MAY, treat it as contract-level requirements. Everything else (examples, command names, JSON shapes) is **illustrative** unless explicitly marked normative.

_Encoding:_ UTF-8.

**Quick links in this consolidated reference:**

- [Appendix C — Design Space Analysis](#appendix-c)
- [Appendix B — Git in Minecraft Analysis](#appendix-b)
- [Appendix A — Version Control Design Template](#appendix-a)
- Adapter interface origin: [B §1.3 Pseudo-interface (`DomainAdapter`)](#b-1-3-domainadapter)


---

## 1. One-line model

Version control is a **content-addressed state graph with named references**. “Files and lines” are just one domain’s atom + diff channel.

---

## 2. The five questions (design levers)

To make version control feel native in a domain, answer these first:

1. **Interaction surface** — Where do users already do the work (canvas, inspector, REPL, chat, command palette)?
2. **Atom** — What’s the smallest unit users perceive as “I changed this”?
3. **Diff channel** — How do users perceive differences (spatial overlays, graph highlights, inline text, waveform markers, cell highlights)?
4. **Fear** — What are they afraid of (loss, breaking shared artifacts, invisible changes, impossible conflicts)?
5. **Minimum loop** — What’s the smallest loop that creates trust: `change → checkpoint → inspect → restore`?

If these are wrong, everything downstream becomes noisy, non-mergeable, or psychologically unsafe.

---

## 3. Architecture: kernel vs adapter

### 3.1 Kernel responsibilities (domain-agnostic)

The kernel is the time-machine substrate. It owns correctness, not meaning:

- checkpoint graph + refs + reflog/recovery
- staging sets / index overlay
- retention + GC roots
- sync + integrity checks
- crash-safe transactions (restore/commit/ref moves/reconcile finalize)
- provenance persistence

### 3.2 Adapter responsibilities (domain semantics)

The adapter is the “physics engine” for meaning and perception:

- deterministic canonicalization + serialization/deserialization
- stable AtomIDs and selector grammar
- semantic diff + domain-native rendering primitives
- merge semantics + conflict detection
- validation + precise localization + (optional) executable fix actions
- dependency closure + risk classification

The kernel **never** interprets domain semantics; it only stores/indexes AtomIDs, ops, and adapter outputs.

---

## 4. The canonical contract surface (normative)

### 4.1 Adapter invariants (MUST)

An adapter implementation MUST uphold:

- **Deterministic canonicalization**: same logical state ⇒ same canonical form.
- **Deterministic serialization/deserialization**: canonical ⇒ identical bytes across runs/machines, and bytes ⇒ same canonical.
- **Stable AtomIDs**: IDs persist across edits/moves/loads/merges; never regenerated on load.
- **Diff determinism + faithfulness**: diffs deterministic; rendering may filter but must not invent.
- **Merge determinism**: same (base, ours, theirs) ⇒ same merged result + conflict set.
- **Validation localizability**: issues localize to atoms (and optionally anchors/regions).
- **Invertibility where claimed**: for operations that claim invertibility, apply+invert returns canonical-equivalent state.

### 4.2 Suggested minimal adapter interface (TypeScript)

_Traceability:_ This interface is derived from **Git in Minecraft Analysis** — [B §1.3 “Pseudo-interface (tight, implementable)”](#b-1-3-domainadapter) (the `DomainAdapter` contract).

```ts
interface DomainAdapter {
  // Determinism core
  canonicalize(state: any): CanonState;
  serialize(canon: CanonState): Uint8Array;
  deserialize(bytes: Uint8Array): CanonState;

  // Edit model
  applyOp(state: any, op: Op): any;
  invertOp(op: Op, stateBefore: any): Op;

  // Perception model
  diff(a: any, b: any): Delta;
  summarize(delta: Delta): HumanSummary;
  renderDelta(delta: Delta, context: any): OverlayPrimitives;

  // Collaboration + safety
  merge(base: any, ours: any, theirs: any): { merged: any; conflicts: Conflict[] };
  validate(state: any): ValidationIssue[];

  // Ergonomics
  dependencies(atoms: AtomID[], state: any): AtomID[];
  risk(op: Op, stateBefore: any): "safe" | "danger";

  // Optional but strongly recommended:
  localize?(x: ValidationIssue | Conflict): { atoms: AtomID[]; anchors?: any; regionHint?: any };
  blobRefs?(canon: CanonState): Uint8Array[]; // if domain has blobs
  compileResolution?(action: any, state: any): Op[]; // or applyResolution
}
```

---

## 5. How A maps onto B (prevent interpretation drift)

The A-template produces a product/spec. To prevent drift, treat these as constrained by the kernel/adapter boundary above:

- **A: Commands & protocol** ⇒ thin interaction layer over kernel APIs (init/status/add/commit/log/diff/reset/branch/merge/sync).
- **A: Data model** ⇒ kernel object model (checkpoint graph, refs, reflog, staged/index objects, reconcile sessions).
- **A: Diff strategy** ⇒ adapter diff + renderDelta + summarize.
- **A: Merge/conflicts/validation** ⇒ adapter merge/validate/localize + kernel reconcile session persistence + validation gating.
- **A: Remotes / “GitHub equivalent”** ⇒ kernel sync/publish semantics + policy hooks (risk-based gating, protections, audit).

Rule of thumb: **A is a spec generator; B is the implementation boundary and invariants; C is how you choose the domain semantics.**

---

## 6. Normative vs illustrative

To avoid confusion:

- Mark every example block as either:
  - **Illustrative example** (valid shape, not required names/fields), or
  - **Normative wire format** (must match for interoperability).

- Keep normative requirements in:
  - Adapter invariants (Section 4.1),
  - Kernel invariants (in the kernel spec),
  - Conformance tests (Section 7).

---

## 7. Conformance tests (CI-friendly checklist)

### 7.1 Adapter conformance (MUST)

1. **Canonicalization idempotence**
   - canonicalize(canonicalize(S)) == canonicalize(S)
2. **Serialization determinism**
   - serialize(canonicalize(S)) stable across runs/machines
3. **Round-trip determinism**
   - canonicalize(deserialize(serialize(canonicalize(S)))) == canonicalize(S)
4. **AtomID stability**
   - load/save/load preserves AtomIDs; rename/move doesn’t regenerate IDs
5. **Diff determinism**
   - diff(A,B) stable ordering and stable grouping; no phantom diffs
6. **Merge determinism**
   - merge(base, ours, theirs) stable output + stable conflict ordering
7. **Validation localization**
   - every issue references atoms and (optionally) anchor metadata
8. **Invertibility (where claimed)**
   - applyOp + invertOp returns canonical-equivalent state
9. **Dependency closure correctness**
   - dependencies([...]) returns deterministic, complete closure set
10. **Risk classification consistency**
   - risk() stable; danger ops flagged reliably

### 7.2 Kernel conformance (SHOULD)

- every destructive transition writes a recovery root (reflog/pre-action snapshot)
- journaled/transactional ref moves survive crashes
- GC is conservative and rooted in refs/reflog/sessions/sync state
- integrity checks on all content-addressed objects

---

## 8. Terminology (canonical terms + UI aliases)

Choose one canonical term set for specs and storage; allow UI aliases.

**Canonical internal terms:**
- **Checkpoint** (immutable, addressable state + metadata)
- **Lane** (branch-like mutable ref namespace)
- **Reconcile** (merge/rebase/cherry-pick concept family)
- **Index** (staging overlay anchored to a base checkpoint)

**UI aliases:**
- “Commit” may be shown as a synonym for **Checkpoint** in Git-fluent modes.
- “Branch” may be shown as a synonym for **Lane**.

---

## 9. The most leveraged next move

Pick one target domain and run the stack end-to-end:

1. Answer the five questions (Section 2) until atom/diff channel/fear/min-loop are crisp.
2. Write the adapter to the contract (Section 4).
3. Use the A-template to generate the product spec, ensuring it is implementable atop the kernel/adapter boundary (Section 5).
4. Write conformance fixtures (Section 7) before you build UI polish.

That produces a “minimum complete proof” that the philosophy cashes out into an implementable contract.
