/**
 * Conformance Config Loader
 *
 * Supports an optional conformance.config.json at the project root (or via CONFORMANCE_CONFIG).
 * When present, adapter-specific conformance tests will run; otherwise they are skipped.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

/**
 * Locate conformance config path.
 * Priority:
 *  1) process.env.CONFORMANCE_CONFIG (absolute or relative)
 *  2) ./conformance.config.json (cwd)
 * @returns {string|null}
 */
export function findConfigPath() {
  const env = process.env.CONFORMANCE_CONFIG;
  if (env && env.trim()) {
    return resolve(env.trim());
  }

  const candidate = resolve(process.cwd(), 'conformance.config.json');
  if (existsSync(candidate)) return candidate;

  return null;
}

/**
 * Load and normalize conformance config.
 * Paths are resolved relative to the config file directory.
 * @param {string} configPath
 */
export function loadConformanceConfig(configPath) {
  const raw = JSON.parse(readFileSync(configPath, 'utf8'));
  const baseDir = dirname(configPath);

  const resolveRel = (p) => (p ? resolve(baseDir, p) : null);

  const cfg = {
    adapter: raw.adapter ? resolveRel(raw.adapter) : null,
    domain_goldens: raw.domain_goldens ? resolveRel(raw.domain_goldens) : null,
    atom_fixtures: raw.atom_fixtures ? resolveRel(raw.atom_fixtures) : null,
    skip: Array.isArray(raw.skip) ? raw.skip : [],
  };

  if (!cfg.adapter) {
    throw new Error('conformance.config.json must include "adapter": "./path/to/adapter.js"');
  }

  return cfg;
}
