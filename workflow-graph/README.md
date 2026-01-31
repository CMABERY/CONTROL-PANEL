# Domain-Native Version Control Kit — Workflow Graph Reference

This repo demonstrates how to build version control that feels native to a domain,
not bolted on. It implements the full stack: philosophy → architecture → spec →
conformance enforcement → working adapter.

**What this certifies:** An adapter that produces deterministic canonical bytes,
stable AtomIDs, faithful diffs, deterministic merges, and localized validation.

**What an adapter must implement:** `canonicalizeDomain`, `diff`, `merge`, `validate`
— all satisfying the invariants in `bundle.schema.json` and passing golden hash vectors.

**The one command:**

```bash
npx flowversion-conformance test
```

If it's green, your adapter upholds the physics. If it's red, it doesn't.

## Structure

- `packages/flowversion-conformance/` — the conformance harness (published package shape)
- `packages/workflow-graph-adapter/` — reference adapter + fixtures + docs

## Kit docs included

For convenience, the full writing stack is vendored here:

- `docs/kit/domain_native_vcs_kit_utf8_bom.md` — glue layer (10-minute engineer read)
- `docs/kit/domain_native_vcs_reference_utf8_bom.md` — consolidated reference
- `docs/kit/A_version_control_design_template.md`
- `docs/kit/B_git_in_minecraft_analysis.md`
- `docs/kit/C_design_space_analysis.md`

## Regenerating Goldens

Goldens are **contract artifacts**, not convenience caches. Regenerating them is a 
**breaking change** unless you're fixing a bug in the canonicalizer itself.

### When regeneration is allowed

- You found a bug in canonicalization that produces incorrect bytes
- You're intentionally changing canonicalization rules (new spec version)
- You're adding new golden vectors (append-only, no modifications)

### When regeneration is NOT allowed

- "CI is red and I don't know why"
- "The hashes changed after I upgraded Node"
- "It works on my machine"

If hashes changed unexpectedly, **that's a bug to investigate**, not a golden to update.

### Regeneration procedure (this repo)

1. **Bump version** in `packages/flowversion-conformance/src/index.js`:
   - `CANON_VERSION` if canonicalization rules changed
   - `SPEC_VERSION` if schema or contract changed

2. **Regenerate goldens**:
   ```bash
   npm -w flowversion-conformance run gen:goldens
   npm -w workflow-graph-adapter-reference run gen:domain-goldens
   ```

3. **Update CHANGELOG.md** with:
   - What changed and why
   - The new `CANON_VERSION` or `SPEC_VERSION`
   - Migration notes for downstream adapters

4. **Review the diff** — goldens changes should be explainable, not mysterious

5. **PR must pass the tripwire** — CI will fail if CHANGELOG doesn't mention the version bump

