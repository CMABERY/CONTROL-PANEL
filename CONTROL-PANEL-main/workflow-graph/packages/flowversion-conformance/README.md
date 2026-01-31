# FlowVersion Conformance Harness

Conformance testing suite for Domain-Native Version Control Kit adapters.

This harness turns the invariants from the VCS Kit into **CI-enforced physics**:
if an adapter passes these tests, it upholds the determinism and correctness
guarantees the kernel depends on.

## Quick Start

```bash
npm install
npm test
```

For quick fixture-only validation:

```bash
npm run validate
```

## CLI

If you prefer a single entrypoint (especially for adapter repos), you can run the harness via `npx`:

```bash
npx flowversion-conformance test
```

Commands:

```bash
npx flowversion-conformance test
npx flowversion-conformance validate
npx flowversion-conformance gen-goldens
npx flowversion-conformance gen-domain-goldens
```

To point at a non-default config file:

```bash
npx flowversion-conformance test --config ./path/to/conformance.config.json
```

## Node version policy

- **Supported:** Node.js **LTS** majors.
- **CI recommendation:** run the suite on at least two adjacent LTS lines (e.g. current Active LTS and current Maintenance LTS).
- **Why:** this harness is a *portability gate*. If it only runs on one Node version, you’ll eventually ship “stable garbage” with a clean test badge.

## What's Tested

### Schema Conformance (Section 7.1 of the Kit)

The `bundle.schema.json` defines wire format for all kernel objects:

- **Index** — Staging overlay with frozen patches
- **PatchOp** — Individual staged change with `from_hash`/`to_hash` (staging freeze)
- **Checkpoint** — Immutable state snapshot with metadata
- **ReconcileSession** — Merge/rebase state with conflicts and resolutions
- **ReflogEntry** — Recovery trail for ref changes
- **ValidationResult** / **ValidationIssue** — Validation with precise localization
- **Conflict** — Merge conflicts with severity and resolution options

Key schema enforcement points:

| Rule | Enforcement |
|------|-------------|
| Staging freeze | `PatchOp.from_hash` and `to_hash` required |
| Warning auto-resolution | `Conflict.severity=warning` requires `default_resolution` |
| Validation localization | `ValidationIssue.atoms` has `minItems: 1` |
| Version tracking | Persisted objects require `v >= 1` |

### Canonicalization Conformance (Invariants 1-3)

The reference canonicalizer (`src/canonicalize.js`) implements:

1. **Idempotence**: `canonicalize(canonicalize(S)) === canonicalize(S)`
2. **Determinism**: `serialize(canonicalize(S))` stable across runs/machines
3. **Round-trip**: `canonicalize(deserialize(serialize(canonicalize(S)))) === canonicalize(S)`

Plus normalization rules:

- Key ordering: lexicographic (Unicode code point)
- UUIDs: lowercase
- Hashes: lowercase
- Timestamps: ISO 8601 with Z suffix
- Numbers: **safe integers only** (no floats). Domain adapters must quantize floats at the boundary (e.g., microunits as integers) and document precision.


### Golden Vectors (Normative)

`goldens.json` contains normative test vectors of the form:

- input JSON
- expected canonical JSON string (byte-for-byte)
- expected SHA-256 hex of those canonical bytes

This is the cross-language convergence test: if another implementation (Go/Rust/Python/etc.)
produces the same canonical bytes + hashes, it is serializing the *same state*.

To regenerate **only when the canonicalization spec version changes**, edit
`scripts/goldens.source.json`, bump its `version`, then run:

```bash
npm run gen:goldens
```

### Fixtures

```
fixtures/
├── valid/           # MUST pass validation
│   ├── index/
│   ├── checkpoint/
│   ├── reconcile_session/
│   ├── reflog_entry/
│   └── validation_result/
└── invalid/         # MUST fail validation
    ├── index/
    ├── checkpoint/
    ├── conflict/
    ├── patch_op/
    └── validation_issue/
```

Each invalid fixture includes `_expected_error` to verify the right validation
rule triggered.

## Using in Your Adapter

### 1. Import the canonicalizer

```javascript
import { canonicalize, serialize, hashCanonical } from 'flowversion-conformance';

// In your adapter's canonicalize implementation:
export function myCanonicalizer(state) {
  // Apply domain-specific normalization first
  const normalized = normalizeDomainState(state);
  // Then use the base canonicalizer
  return canonicalize(normalized);
}
```

### 2. Validate your objects against the schema

```javascript
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { loadSchema } from 'flowversion-conformance';

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
ajv.addSchema(loadSchema());

const validateCheckpoint = ajv.compile({
  $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Checkpoint'
});

// In your tests:
assert(validateCheckpoint(myCheckpoint), validateCheckpoint.errors);
```

### 3. Add your own golden fixtures

Create `fixtures/domain/` with domain-specific test cases that exercise your
adapter's `diff`, `merge`, `validate`, and `localize` implementations.

## Conformance Checklist

From Section 7 of the Domain-Native VCS Kit:

### Adapter Conformance (MUST)

- [ ] Canonicalization idempotence
- [ ] Serialization determinism
- [ ] Round-trip determinism
- [ ] AtomID stability
- [ ] Diff determinism
- [ ] Merge determinism
- [ ] Validation localization
- [ ] Invertibility (where claimed)
- [ ] Dependency closure correctness
- [ ] Risk classification consistency

### Kernel Conformance (SHOULD)

- [ ] Recovery root on destructive transitions
- [ ] Journaled/transactional ref moves
- [ ] Conservative GC rooted in refs/reflog/sessions
- [ ] Integrity checks on content-addressed objects

## Files

| File | Purpose |
|------|---------|
| `bundle.schema.json` | JSON Schema (Draft 2020-12) for all kernel objects |
| `src/canonicalize.js` | Reference canonicalizer implementation |
| `src/schema.test.js` | Schema validation tests |
| `src/canonicalization.test.js` | Canonicalization invariant tests |
| `src/validate-fixtures.js` | Quick fixture validation CLI |
| `fixtures/` | Valid and invalid test fixtures |

## License

MIT


## Adapter Extension Pattern (Certification Mode)

This harness can also certify a **domain adapter**, not just kernel objects.

### Add a conformance config

Create `conformance.config.json` (or copy `conformance.config.example.json`) at the repo root:

```json
{
  "adapter": "./my-adapter.js",
  "domain_goldens": "./domain-goldens.json",
  "atom_fixtures": "./atoms",
  "skip": []
}
```

Or point to it explicitly:

```bash
CONFORMANCE_CONFIG=./path/to/conformance.config.json npm test
```

### Adapter module contract

Your adapter module should export (minimum):

- `canonicalizeDomain(value)` → returns a value that is **already in base canonical form**  
  (`canonicalize(canonicalizeDomain(x)) === canonicalizeDomain(x)`).

Optional (only used if fixtures exist):

- `diff(fromAtom, toAtom)`
- `merge(baseAtom, leftAtom, rightAtom)`
- `validate(atomOrState)` → must return a `$defs/ValidationResult`-shaped object

### Domain golden vectors (normative)

If `domain_goldens` is provided, the harness will enforce that for each vector:

- `bytes = serialize(canonicalize(canonicalizeDomain(input)))`
- `sha256 = SHA-256(bytes)`

The file format matches `goldens.json`:

```json
{
  "version": 1,
  "vectors": [
    { "name": "…", "input": {...}, "canonical_json": "…", "sha256": "…" }
  ]
}
```

You can start from `domain-goldens.example.json`. Typically you generate/update
these only when you bump your adapter’s canonicalization spec version.

### Atom fixtures (optional)

If `atom_fixtures` is provided, the harness looks for:

- `atoms/diff/*.json` with `{ name?, from, to }`
- `atoms/merge/*.json` with `{ name?, base, left, right }`
- `atoms/validate/*.json` with `{ name?, input }`

The tests are **determinism-first** (same input → same output bytes).  
If you add an `expect` block to a fixture, the harness will also assert **semantic expectations**
for that output. This prevents “deterministic nonsense” from passing.

You can opt out via `skip`, e.g. `["merge"]`.

#### Merge expectations (`atoms/merge/*.json`)

Add an optional `expect` object:

```json
{
  "base": { "...": "..." },
  "left": { "...": "..." },
  "right": { "...": "..." },
  "expect": {
    "conflict_count": 1,
    "conflicts": [
      {
        "type": "edit_edit",
        "severity": "error",
        "selector_pattern": "^node:abc"
      }
    ]
  }
}
```

Rules:
- `conflict_count` / `conflict_count_min` / `conflict_count_max` check the length of `mergeResult.conflicts`.
- Each entry in `expect.conflicts` must match **at least one** actual conflict.
- `selector_pattern` and `type_pattern` are **regex strings**.

Note: to apply merge expectations, your `merge()` output must expose a `conflicts[]` array
either at the top level (`{ conflicts: [...] }`) or under common wrappers (`session`, `reconcile_session`, etc).

#### Validate expectations (`atoms/validate/*.json`)

Add an optional `expect` object:

```json
{
  "input": { "...": "..." },
  "expect": {
    "valid": false,
    "issue_codes": ["MISSING_REQUIRED_FIELD", "ORPHAN_EDGE"],
    "atoms_mentioned": ["^node:fraud_check$", "^edge:fraud_check->payment$"]
  }
}
```

Rules:
- `valid` checks `ValidationResult.valid`.
- `issue_codes` is a **subset** requirement by default (each code must appear at least once).
- Set `issue_codes_exact: true` to require exact code set equality (order-insensitive).
- `atoms_mentioned` entries are **regex strings** matched against the union of all `issue.atoms`.

All validate outputs are still required to conform to `$defs/ValidationResult` in `bundle.schema.json`.


### Generating domain goldens

If you maintain a `domain_goldens` file, you can refresh its `canonical_json` and `sha256`
using the configured adapter:

```bash
npm run gen:domain-goldens
```

This reads `conformance.config.json`, loads your adapter, and overwrites the vectors'
`canonical_json` and `sha256` fields.

**Do not run this in CI.** Regenerate only when you intentionally change the adapter's
canonicalization spec and bump your domain goldens `version`.
