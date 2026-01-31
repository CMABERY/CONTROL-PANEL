/**
 * Generate/refresh domain goldens using the configured adapter.
 *
 * Usage:
 *   node scripts/generate-domain-goldens.mjs
 *
 * Requires:
 *   - conformance.config.json (or CONFORMANCE_CONFIG)
 *   - config.domain_goldens points to a JSON file with { version, vectors: [{name,input,...}] }
 *
 * This script overwrites canonical_json + sha256 for each vector based on:
 *   bytes = serialize(canonicalize(canonicalizeDomain(input)))
 *   sha256 = SHA-256(bytes)
 *
 * WARNING:
 *   Regenerate only when you intentionally change the adapter canonicalization spec.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { findConfigPath, loadConformanceConfig } from '../src/config.js';
import { loadAdapter } from '../src/load-adapter.js';
import { canonicalize, serialize, hashCanonical } from '../src/canonicalize.js';
import { SPEC_VERSION, CANON_VERSION } from '../src/index.js';

const configPath = findConfigPath();
if (!configPath) {
  console.error('No conformance.config.json found. Set CONFORMANCE_CONFIG or create one.');
  process.exit(1);
}

const cfg = loadConformanceConfig(configPath);
if (!cfg.domain_goldens) {
  console.error('conformance.config.json must set "domain_goldens" to use this generator.');
  process.exit(1);
}

const adapter = await loadAdapter(cfg.adapter);
if (!adapter || typeof adapter.canonicalizeDomain !== 'function') {
  console.error('Adapter must export canonicalizeDomain(value).');
  process.exit(1);
}

const goldens = JSON.parse(readFileSync(cfg.domain_goldens, 'utf8'));
if (!goldens || !Array.isArray(goldens.vectors)) {
  console.error('domain_goldens must have shape: { version, vectors: [...] }');
  process.exit(1);
}

goldens._meta = {
  spec_version: SPEC_VERSION,
  canon_version: CANON_VERSION,
  generated_at: new Date().toISOString(),
  generator: 'flowversion-conformance'
};

for (const vec of goldens.vectors) {
  const domainCanon = adapter.canonicalizeDomain(vec.input);
  const baseCanon = canonicalize(domainCanon);
  const bytes = serialize(baseCanon);
  const json = new TextDecoder().decode(bytes);
  const hash = await hashCanonical(baseCanon);

  vec.canonical_json = json;
  vec.sha256 = hash;
}

writeFileSync(cfg.domain_goldens, JSON.stringify(goldens, null, 2) + '\n', 'utf8');
console.log(`Wrote updated domain goldens to: ${cfg.domain_goldens}`);
