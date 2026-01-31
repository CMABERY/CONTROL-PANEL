/**
 * Adapter loader
 *
 * Adapters may be ESM exports or a default-exported object.
 *
 * Expected exports (minimum):
 *   - canonicalizeDomain(value): any
 *
 * Optional exports used if fixtures are provided:
 *   - diff(fromAtom, toAtom): any
 *   - merge(baseAtom, leftAtom, rightAtom): any
 *   - validate(atomOrState): ValidationResult-like object
 */

import { pathToFileURL } from 'node:url';

/**
 * @param {string} adapterPath - absolute filesystem path
 * @returns {Promise<object>}
 */
export async function loadAdapter(adapterPath) {
  const mod = await import(pathToFileURL(adapterPath).href);

  // Prefer default-exported object if it looks like an adapter
  const candidate =
    (mod && mod.default && typeof mod.default === 'object')
      ? mod.default
      : mod;

  // If the adapter is a function (rare), allow it as default canonicalizer
  if (typeof candidate === 'function') {
    return { canonicalizeDomain: candidate };
  }

  return candidate;
}
