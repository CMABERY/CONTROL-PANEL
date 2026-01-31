# Regenerating Goldens

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
