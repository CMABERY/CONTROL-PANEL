/**
 * Adapter Extension Conformance Suite
 *
 * This suite is optional and runs only when a conformance config is present.
 *
 * Config (project root):
 *   conformance.config.json
 *
 * Env override:
 *   CONFORMANCE_CONFIG=/abs/or/rel/path/to/conformance.config.json
 *
 * The adapter module is expected to export:
 *   - canonicalizeDomain(value)
 *
 * Optionally:
 *   - diff(fromAtom, toAtom)
 *   - merge(baseAtom, leftAtom, rightAtom)
 *   - validate(atomOrState)
 *
 * If domain_goldens is provided, vectors are treated as NORMATIVE for the adapter:
 *   canonicalizeDomain(input) -> canonical value (must also satisfy base canonicalize())
 *   bytes = serialize(baseCanonicalValue)
 *   sha256 = SHA-256(bytes)
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, extname } from 'node:path';

import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

import { canonicalize, serialize, deserialize, hashCanonical, canonicalEqual } from './canonicalize.js';
import { loadSchema } from './index.js';
import { findConfigPath, loadConformanceConfig } from './config.js';
import { loadAdapter } from './load-adapter.js';

function shouldSkip(cfg, name) {
  return Array.isArray(cfg.skip) && cfg.skip.includes(name);
}

function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'));
}

function listJsonFiles(dir) {
  if (!dir || !existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => extname(f).toLowerCase() === '.json')
    .map((f) => join(dir, f));
}


// ---------- Semantic expectation helpers (optional) ----------

function compileRegex(pattern, label) {
  try {
    return new RegExp(pattern);
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    throw new Error(`Invalid regex for ${label}: ${pattern}. ${msg}`);
  }
}

function unique(arr) {
  return Array.from(new Set(arr));
}

function extractConflicts(mergeResult) {
  if (!mergeResult || typeof mergeResult !== 'object') return null;

  if (Array.isArray(mergeResult.conflicts)) return mergeResult.conflicts;

  // Common wrapper shapes: { session: { conflicts: [...] } } etc.
  const candidates = ['session', 'reconcile_session', 'reconcileSession', 'reconcile', 'result', 'merge_result'];
  for (const k of candidates) {
    const v = mergeResult[k];
    if (v && typeof v === 'object' && Array.isArray(v.conflicts)) return v.conflicts;
  }

  return null;
}

function summarizeConflicts(conflicts) {
  if (!Array.isArray(conflicts)) return [];
  return conflicts.map((c) => ({
    type: c && typeof c === 'object' ? c.type : undefined,
    severity: c && typeof c === 'object' ? c.severity : undefined,
    selector: c && typeof c === 'object' ? c.selector : undefined,
  }));
}

function conflictMatchesSpec(conflict, spec) {
  if (!conflict || typeof conflict !== 'object') return false;
  if (!spec || typeof spec !== 'object') return false;

  if (spec.type !== undefined && conflict.type !== spec.type) return false;
  if (spec.severity !== undefined && conflict.severity !== spec.severity) return false;
  if (spec.selector !== undefined && conflict.selector !== spec.selector) return false;

  if (spec.type_pattern !== undefined) {
    const re = compileRegex(spec.type_pattern, 'conflict.type_pattern');
    if (!re.test(String(conflict.type ?? ''))) return false;
  }

  if (spec.selector_pattern !== undefined) {
    const re = compileRegex(spec.selector_pattern, 'conflict.selector_pattern');
    if (!re.test(String(conflict.selector ?? ''))) return false;
  }

  return true;
}

function assertMergeExpectations(expect, mergeResult, label) {
  if (!expect || typeof expect !== 'object') return;

  const conflicts = extractConflicts(mergeResult);
  assert.ok(Array.isArray(conflicts), `merge() expectations require merge output to expose a conflicts[] array (fixture: ${label})`);

  // Count checks
  if (expect.conflict_count !== undefined) {
    assert.equal(conflicts.length, expect.conflict_count, `Expected conflict_count=${expect.conflict_count} but got ${conflicts.length} (fixture: ${label}). Actual: ${JSON.stringify(summarizeConflicts(conflicts))}`);
  }
  if (expect.conflict_count_min !== undefined) {
    assert.ok(conflicts.length >= expect.conflict_count_min, `Expected conflict_count >= ${expect.conflict_count_min} but got ${conflicts.length} (fixture: ${label}). Actual: ${JSON.stringify(summarizeConflicts(conflicts))}`);
  }
  if (expect.conflict_count_max !== undefined) {
    assert.ok(conflicts.length <= expect.conflict_count_max, `Expected conflict_count <= ${expect.conflict_count_max} but got ${conflicts.length} (fixture: ${label}). Actual: ${JSON.stringify(summarizeConflicts(conflicts))}`);
  }

  // Pattern checks (each expected entry must match at least one actual conflict)
  if (Array.isArray(expect.conflicts)) {
    for (const [i, spec] of expect.conflicts.entries()) {
      const ok = conflicts.some((c) => conflictMatchesSpec(c, spec));
      assert.ok(
        ok,
        `Expected conflict pattern #${i} did not match any actual conflict (fixture: ${label}). Expected: ${JSON.stringify(spec)}. Actual: ${JSON.stringify(summarizeConflicts(conflicts))}`
      );
    }
  }

  // Optional strictness: no unexpected conflicts beyond what patterns cover
  if (expect.no_unexpected_conflicts && Array.isArray(expect.conflicts)) {
    const unexpected = conflicts.filter((c) => !expect.conflicts.some((spec) => conflictMatchesSpec(c, spec)));
    assert.equal(
      unexpected.length,
      0,
      `Found unexpected conflicts not covered by expectations (fixture: ${label}). Unexpected: ${JSON.stringify(summarizeConflicts(unexpected))}. Actual: ${JSON.stringify(summarizeConflicts(conflicts))}`
    );
  }
}

function assertValidateExpectations(expect, validationResult, label) {
  if (!expect || typeof expect !== 'object') return;

  const vr = validationResult;
  assert.ok(vr && typeof vr === 'object', `validate() must return an object to apply expectations (fixture: ${label})`);
  const issues = Array.isArray(vr.issues) ? vr.issues : [];

  if (expect.valid !== undefined) {
    assert.equal(vr.valid, expect.valid, `Expected valid=${expect.valid} but got ${vr.valid} (fixture: ${label})`);
  }

  if (expect.issue_count !== undefined) {
    assert.equal(issues.length, expect.issue_count, `Expected issue_count=${expect.issue_count} but got ${issues.length} (fixture: ${label})`);
  }
  if (expect.issue_count_min !== undefined) {
    assert.ok(issues.length >= expect.issue_count_min, `Expected issue_count >= ${expect.issue_count_min} but got ${issues.length} (fixture: ${label})`);
  }
  if (expect.issue_count_max !== undefined) {
    assert.ok(issues.length <= expect.issue_count_max, `Expected issue_count <= ${expect.issue_count_max} but got ${issues.length} (fixture: ${label})`);
  }

  const codes = issues.map((i) => i && typeof i === 'object' ? i.code : undefined).filter((c) => typeof c === 'string');
  const codeSet = new Set(codes);

  if (Array.isArray(expect.issue_codes)) {
    for (const c of expect.issue_codes) {
      assert.ok(codeSet.has(c), `Expected issue code "${c}" not found (fixture: ${label}). Actual codes: ${JSON.stringify(unique(codes))}`);
    }

    if (expect.issue_codes_exact) {
      const expectedSet = new Set(expect.issue_codes);
      const actualSet = new Set(unique(codes));

      const missing = Array.from(expectedSet).filter((c) => !actualSet.has(c));
      const extra = Array.from(actualSet).filter((c) => !expectedSet.has(c));

      assert.equal(
        missing.length + extra.length,
        0,
        `Expected exact issue codes did not match (fixture: ${label}). Missing: ${JSON.stringify(missing)}. Extra: ${JSON.stringify(extra)}. Actual: ${JSON.stringify(Array.from(actualSet))}`
      );
    }
  }

  const atoms = issues
    .flatMap((i) => (i && typeof i === 'object' && Array.isArray(i.atoms) ? i.atoms : []))
    .filter((a) => typeof a === 'string');

  if (Array.isArray(expect.atoms_mentioned)) {
    for (const pattern of expect.atoms_mentioned) {
      const re = compileRegex(pattern, 'atoms_mentioned[]');
      const ok = atoms.some((a) => re.test(a));
      assert.ok(ok, `Expected an atom matching /${pattern}/ not found (fixture: ${label}). Actual atoms: ${JSON.stringify(unique(atoms))}`);
    }
  }
}

describe('Adapter Conformance (Extension Pattern)', () => {
  const configPath = findConfigPath();

  if (!configPath) {
    test('No conformance.config.json found (skipping adapter suite)', { skip: true }, () => {});
    return;
  }

  let cfg;
  try {
    cfg = loadConformanceConfig(configPath);
  } catch (e) {
    test('Invalid conformance.config.json', () => { throw e; });
    return;
  }

  test('Config loads and adapter path exists', () => {
    assert.ok(cfg.adapter, 'Missing adapter path');
    assert.ok(existsSync(cfg.adapter), `Adapter module not found: ${cfg.adapter}`);
  });
  // Load adapter once for all tests.
  let adapter;
  before(async () => {
    adapter = await loadAdapter(cfg.adapter);
  });

  test('Adapter module loads and exports canonicalizeDomain', () => {
    assert.ok(adapter, 'Adapter did not load');
    assert.equal(typeof adapter.canonicalizeDomain, 'function', 'Adapter must export canonicalizeDomain(value)');
  });

  // --- Base adapter canonicalization invariants ---
  describe('canonicalizeDomain invariants', () => {
    test('Determinism: canonicalizeDomain(input) is stable', async () => {
      const input = { z: 2, a: 1, nested: { b: 2, a: 1 } };

      const d1 = adapter.canonicalizeDomain(input);
      const d2 = adapter.canonicalizeDomain(input);

      // Compare in base-canonical form to avoid false negatives due to key order.
      assert.ok(canonicalEqual(d1, d2), 'canonicalizeDomain must be deterministic for the same input');
    });

    test('Idempotence: canonicalizeDomain(canonicalizeDomain(x)) === canonicalizeDomain(x) (in base-canonical form)', () => {
      const input = { arr: [3, 2, 1], obj: { b: 2, a: 1 } };
      const once = adapter.canonicalizeDomain(input);
      const twice = adapter.canonicalizeDomain(once);

      assert.ok(canonicalEqual(once, twice), 'canonicalizeDomain must be idempotent');
    });

    test('Kernel portability: output must satisfy base canonicalize()', () => {
      const input = { coords: { x: 123, y: 456 }, ts: '2024-01-15T10:00:00-08:00' };
      const out = adapter.canonicalizeDomain(input);

      // This will throw if the adapter returns floats/unsafe ints/undefined, etc.
      const baseCanon = canonicalize(out);

      // Strong recommendation: adapter returns already-base-canonical output.
      // If base canonicalize changes it, you are relying on the kernel to "fix" your output,
      // which is a common source of interop drift.
      assert.deepEqual(baseCanon, out, 'canonicalizeDomain output must already be in base canonical form (canonicalize(out) === out)');
    });

    test('Round-trip: deserialize(serialize(canonicalizeDomain(x))) is canonical-equivalent', () => {
      const input = { k: 'v', list: [1, 2, 3] };
      const out = adapter.canonicalizeDomain(input);

      const bytes = serialize(out);
      const back = deserialize(bytes);

      assert.ok(canonicalEqual(out, back), 'Round-trip should preserve canonical form');
    });
  });

  // --- Domain golden vectors ---
  describe('Domain Golden Vectors (optional, normative)', () => {
    if (!cfg.domain_goldens) {
      test('No domain_goldens provided (skipping)', { skip: true }, () => {});
      return;
    }

    if (shouldSkip(cfg, 'domain_goldens')) {
      test('domain_goldens skipped via config', { skip: true }, () => {});
      return;
    }

    test('domain_goldens file exists', () => {
      assert.ok(existsSync(cfg.domain_goldens), `domain_goldens not found: ${cfg.domain_goldens}`);
    });

    const { version, vectors } = readJson(cfg.domain_goldens);

    test('domain_goldens has expected shape', () => {
      assert.ok(Number.isInteger(version) && version >= 1);
      assert.ok(Array.isArray(vectors));
      assert.ok(vectors.length >= 1);
    });

    for (const vec of vectors || []) {
      test(`Domain golden: ${vec.name}`, async () => {
        const domainCanon = adapter.canonicalizeDomain(vec.input);

        // Enforce kernel portability + ensure stable bytes/hashes.
        const baseCanon = canonicalize(domainCanon);
        const bytes = serialize(baseCanon);
        const json = new TextDecoder().decode(bytes);
        const hash = await hashCanonical(baseCanon);

        assert.equal(json, vec.canonical_json, `Canonical JSON mismatch for ${vec.name}`);
        assert.equal(hash, vec.sha256, `Hash mismatch for ${vec.name}`);
        assert.match(hash, /^[a-f0-9]{64}$/);
      });
    }
  });

// --- Optional diff/merge/validate determinism tests ---
  describe('Diff/Merge/Validate determinism (optional)', () => {
    if (!cfg.atom_fixtures || !existsSync(cfg.atom_fixtures)) {
      test('No atom_fixtures provided (skipping)', { skip: true }, () => {});
      return;
    }

    const diffDir = join(cfg.atom_fixtures, 'diff');
    const mergeDir = join(cfg.atom_fixtures, 'merge');
    const validateDir = join(cfg.atom_fixtures, 'validate');

    const diffFiles = listJsonFiles(diffDir);
    const mergeFiles = listJsonFiles(mergeDir);
    const validateFiles = listJsonFiles(validateDir);

    // Compile fixture + output validators once (sharper diagnostics)
    const ajv = new Ajv({ strict: false, allErrors: true });
    addFormats(ajv);
    const bundle = loadSchema();
    ajv.addSchema(bundle, 'bundle');

    const validateDiffFixture = ajv.compile({ $ref: 'bundle#/$defs/DiffFixture' });
    const validateMergeFixture = ajv.compile({ $ref: 'bundle#/$defs/MergeFixture' });
    const validateValidateFixture = ajv.compile({ $ref: 'bundle#/$defs/ValidateFixture' });
    const validateResult = ajv.compile({ $ref: 'bundle#/$defs/ValidationResult' });

    const canUse = (fnName) => typeof adapter?.[fnName] === 'function' && !shouldSkip(cfg, fnName);

    // ---- diff() ----
    for (const p of diffFiles) {
      const fx = readJson(p);
      const name = fx.name || p.split('/').pop();

      test(`diff fixture schema: ${name}`, (t) => {
        if (!canUse('diff')) return t.skip();

        const ok = validateDiffFixture(fx);
        assert.ok(
          ok,
          `Malformed diff fixture: ${p}. Errors: ${JSON.stringify(validateDiffFixture.errors)}`
        );
      });

      test(`diff deterministic: ${name}`, (t) => {
        if (!canUse('diff')) return t.skip();

        const ok = validateDiffFixture(fx);
        assert.ok(
          ok,
          `Malformed diff fixture: ${p}. Errors: ${JSON.stringify(validateDiffFixture.errors)}`
        );

        // Extra args are ignored in JS, so passing options is safe even if the adapter doesn't use them.
        const d1 = adapter.diff(fx.from, fx.to, fx.options);
        const d2 = adapter.diff(fx.from, fx.to, fx.options);

        // Force base canonical form so comparison is stable.
        const c1 = canonicalize(d1);
        const c2 = canonicalize(d2);
        assert.deepEqual(c1, c2, 'diff() output must be deterministic and JSON-stable');
      });
    }

    test('diff fixtures present (or directory absent)', (t) => {
      if (!canUse('diff')) return t.skip();
      // Not a failure if no diff fixtures exist; this is a kit, not a prison.
      assert.ok(true);
    });

    // ---- merge() ----
    for (const p of mergeFiles) {
      const fx = readJson(p);
      const name = fx.name || p.split('/').pop();

      test(`merge fixture schema: ${name}`, (t) => {
        if (!canUse('merge')) return t.skip();

        const ok = validateMergeFixture(fx);
        assert.ok(
          ok,
          `Malformed merge fixture: ${p}. Errors: ${JSON.stringify(validateMergeFixture.errors)}`
        );
      });

      test(`merge deterministic: ${name}`, (t) => {
        if (!canUse('merge')) return t.skip();

        const ok = validateMergeFixture(fx);
        assert.ok(
          ok,
          `Malformed merge fixture: ${p}. Errors: ${JSON.stringify(validateMergeFixture.errors)}`
        );

        const m1 = adapter.merge(fx.base, fx.left, fx.right, fx.options);
        const m2 = adapter.merge(fx.base, fx.left, fx.right, fx.options);

        const c1 = canonicalize(m1);
        const c2 = canonicalize(m2);
        assert.deepEqual(c1, c2, 'merge() output must be deterministic and JSON-stable');

        if (fx.expect) {
          assertMergeExpectations(fx.expect, c1, name);
        }
      });
    }

    test('merge fixtures present (or directory absent)', (t) => {
      if (!canUse('merge')) return t.skip();
      assert.ok(true);
    });

    // ---- validate() ----
    for (const p of validateFiles) {
      const fx = readJson(p);
      const name = fx.name || p.split('/').pop();

      test(`validate fixture schema: ${name}`, (t) => {
        if (!canUse('validate')) return t.skip();

        const ok = validateValidateFixture(fx);
        assert.ok(
          ok,
          `Malformed validate fixture: ${p}. Errors: ${JSON.stringify(validateValidateFixture.errors)}`
        );
      });

      test(`validate deterministic + schema: ${name}`, (t) => {
        if (!canUse('validate')) return t.skip();

        const okFx = validateValidateFixture(fx);
        assert.ok(
          okFx,
          `Malformed validate fixture: ${p}. Errors: ${JSON.stringify(validateValidateFixture.errors)}`
        );

        const r1 = adapter.validate(fx.input, fx.options);
        const r2 = adapter.validate(fx.input, fx.options);

        const c1 = canonicalize(r1);
        const c2 = canonicalize(r2);
        assert.deepEqual(c1, c2, 'validate() output must be deterministic');

        const ok = validateResult(c1);
        assert.ok(
          ok,
          `validate() output must conform to $defs/ValidationResult. Errors: ${JSON.stringify(validateResult.errors)}`
        );

        if (fx.expect) {
          assertValidateExpectations(fx.expect, c1, name);
        }
      });
    }

    test('validate fixtures present (or directory absent)', (t) => {
      if (!canUse('validate')) return t.skip();
      assert.ok(true);
    });
  });

});
