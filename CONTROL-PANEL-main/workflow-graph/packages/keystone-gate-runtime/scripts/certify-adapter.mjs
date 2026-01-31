/**
 * Phase 4: Adapter certification artifact generator.
 *
 * This is NOT production code. It is a deterministic certifier used to
 * generate ledger artifacts from conformance results.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { CpoKernel } from '../src/cpo-kernel.js';
import { canonicalizeEnvelope, hashEnvelope, validateEnvelope } from '../src/flowversion-envelope.js';

const CONFORMANCE = JSON.parse(readFileSync(join('goldens', 'conformance.goldens.json'), 'utf8'));

function sha256Utf8(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function deepClone(x) {
  return JSON.parse(JSON.stringify(x));
}

function applySetup(kernel, setup) {
  if (!setup || !Array.isArray(setup.accepted_prereqs)) return;
  for (const p of setup.accepted_prereqs) {
    const v = validateEnvelope(p.input);
    if (!v.ok) throw new Error(`invalid prereq in setup: ${p.record_type}`);
    const h = hashEnvelope(p.input);
    if (h !== p.sha256) throw new Error(`setup hash mismatch: ${p.record_type}`);
    const res = kernel.commit_action(p.record_type, p.sha256, deepClone(p.input));
    if (!res.ok) throw new Error(`setup commit failed: ${p.record_type}`);
  }
}

/**
 * Execute the conformance suite and return a deterministic results manifest.
 */
function runSuite() {
  const results = {};

  for (const v of CONFORMANCE.vectors) {
    const kernel = new CpoKernel();
    applySetup(kernel, v.setup);

    let ok = true;
    if (v.producer_variants) {
      for (const pv of v.producer_variants) {
        const record_type = pv.input.record_type;
        const declared = pv.declared_envelope_hash;
        const res = kernel.commit_action(record_type, declared, deepClone(pv.input));
        if (v.expectation.overall === 'accept') {
          ok = ok && res.ok === true;
        } else {
          ok = ok && res.ok === false && res.classification === v.expectation.classification;
        }
      }
    } else {
      // single-submission vectors
      const record_type = v.input.record_type;
      const declared = v.declared_envelope_hash || '0'.repeat(64);
      const res = kernel.commit_action(record_type, declared, deepClone(v.input));
      ok = v.expectation.overall === 'reject' && res.ok === false && res.classification === v.expectation.classification;
    }
    results[v.name] = ok;
  }

  return results;
}

// -----------------------------
// Certification target (locked)
// -----------------------------

const adapter_id = 'adapter.http';
const certified_version = '1.0.0-test';
const generated_at_ms = 1769817609000;

// In-scope vectors for this adapter class (tool adapter):
// - include all vectors in suite (fail-closed)
const suite_results = runSuite();

// Convert results into deterministic StringSets (maps) to avoid array ordering issues.
const passed = {};
const failed = {};
let passCount = 0;
let failCount = 0;
for (const name of Object.keys(suite_results).sort()) {
  if (suite_results[name]) {
    passed[name] = true;
    passCount++;
  } else {
    failed[name] = true;
    failCount++;
  }
}

const results_manifest = {
  spec_version: CONFORMANCE._meta.spec_version,
  canon_version: CONFORMANCE._meta.canon_version,
  suite_sha256: CONFORMANCE._meta.suite_sha256,
  passed,
  failed,
  summary: { passed: passCount, failed: failCount }
};

const results_manifest_canonical = canonicalizeEnvelope(results_manifest);
const conformance_results_sha256 = sha256Utf8(results_manifest_canonical);

const certification = {
  spec_version: CONFORMANCE._meta.spec_version,
  canon_version: CONFORMANCE._meta.canon_version,
  artifact_type: 'adapter_certification',
  generated_at_ms,
  adapter_id,
  certified_version,
  suite: {
    name: CONFORMANCE.suite.name,
    version: CONFORMANCE.suite.version,
    suite_sha256: CONFORMANCE._meta.suite_sha256
  },
  conformance_results_sha256,
  results: {
    status: failCount === 0 ? 'certified' : 'failed',
    passed,
    failed,
    summary: { passed: passCount, failed: failCount }
  }
};

const certification_canonical_json = canonicalizeEnvelope(certification);
const certification_sha256 = sha256Utf8(certification_canonical_json);

mkdirSync(join('certifications', 'accepted'), { recursive: true });
const outPath = join('certifications', 'accepted', `${certification_sha256}.json`);
writeFileSync(outPath, certification_canonical_json + '\n', 'utf8');

console.log(JSON.stringify({
  adapter_id,
  certified_version,
  status: certification.results.status,
  certification_sha256,
  outPath
}, null, 2));
