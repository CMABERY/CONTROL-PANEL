/**
 * Reference Canonicalizer for Domain-Native VCS
 * 
 * This implements the determinism rules that all adapters MUST follow:
 * - Key ordering: lexicographic (Unicode code point order)
 * - Number formatting: no trailing zeros, no leading zeros (except 0.x), no +exponent
 * - Null vs absent: explicit distinction
 * - Array ordering: stable (not sorted unless domain specifies)
 * - UUID normalization: lowercase
 * - Timestamp normalization: ISO 8601 with Z suffix
 * 
 * Adapters may extend this with domain-specific rules but MUST NOT violate these base rules.
 */

import { webcrypto as crypto } from 'node:crypto';

/**
 * Canonicalize a value according to the base determinism rules.
 * @param {any} value - The value to canonicalize
 * @returns {any} - The canonical form
 */
export function canonicalize(value) {
  if (value === null) {
    return null;
  }

  if (value === undefined) {
    // Undefined is not valid in canonical form - caller must handle absent vs null
    throw new Error('Undefined is not valid in canonical form. Use null or omit the key.');
  }

  const type = typeof value;

  if (type === 'boolean') {
    return value;
  }

  if (type === 'number') {
    return canonicalizeNumber(value);
  }

  if (type === 'string') {
    return canonicalizeString(value);
  }

  if (Array.isArray(value)) {
    return canonicalizeArray(value);
  }

  if (type === 'object') {
    return canonicalizeObject(value);
  }

  throw new Error(`Unsupported type: ${type}`);
}

/**
 * Canonicalize a number.
 * - NaN and Infinity are not allowed
 * - Integers should not have decimal point
 * - Decimals should not have trailing zeros
 */
function canonicalizeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new Error(`Non-finite numbers not allowed in canonical form: ${n}`);
  }

  // Kernel-layer persisted objects MUST be portable across languages/runtimes.
  // That means: integers only, within JavaScript's safe integer range.
  //
  // Domains that require floats MUST quantize at the adapter boundary
  // (e.g., store microunits as integers) and document the precision contract.
  if (!Number.isInteger(n)) {
    throw new Error(`Non-integer numbers are not allowed in canonical form: ${n}`);
  }

  if (!Number.isSafeInteger(n)) {
    throw new Error(`Unsafe integer (exceeds MAX_SAFE_INTEGER) not allowed in canonical form: ${n}`);
  }

  return n;
}

/**
 * Canonicalize a string.
 * - UUIDs normalized to lowercase
 * - Timestamps normalized to ISO 8601 with Z suffix
 * - Other strings unchanged
 */
function canonicalizeString(s) {
  // UUID pattern: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
  if (uuidPattern.test(s)) {
    return s.toLowerCase();
  }

  // ISO 8601 timestamp pattern (simplified)
  const isoPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
  if (isoPattern.test(s)) {
    return normalizeTimestamp(s);
  }

  // Hash pattern (64 hex chars)
  const hashPattern = /^[0-9a-fA-F]{64}$/;
  if (hashPattern.test(s)) {
    return s.toLowerCase();
  }

  return s;
}

/**
 * Normalize a timestamp to canonical form.
 * - Always UTC (Z suffix)
 * - Milliseconds included if non-zero, otherwise omitted
 */
function normalizeTimestamp(s) {
  const date = new Date(s);
  if (isNaN(date.getTime())) {
    throw new Error(`Invalid timestamp: ${s}`);
  }
  
  const ms = date.getUTCMilliseconds();
  if (ms === 0) {
    return date.toISOString().replace('.000Z', 'Z');
  }
  return date.toISOString();
}

/**
 * Canonicalize an array.
 * - Elements canonicalized recursively
 * - Order preserved (arrays are not sorted by default)
 */
function canonicalizeArray(arr) {
  return arr.map(item => canonicalize(item));
}

/**
 * Canonicalize an object.
 * - Keys sorted lexicographically (Unicode code point order)
 * - Values canonicalized recursively
 * - Undefined values are omitted (not the same as null)
 */
function canonicalizeObject(obj) {
  const keys = Object.keys(obj).sort();
  const result = {};
  
  for (const key of keys) {
    const value = obj[key];
    if (value !== undefined) {
      result[key] = canonicalize(value);
    }
  }
  
  return result;
}

/**
 * Serialize a canonical value to deterministic JSON bytes.
 * @param {any} value - Already-canonicalized value
 * @returns {Uint8Array} - UTF-8 encoded JSON bytes
 */
export function serialize(value) {
  const json = JSON.stringify(value);
  return new TextEncoder().encode(json);
}

/**
 * Deserialize JSON bytes to a value, then canonicalize.
 * @param {Uint8Array} bytes - UTF-8 encoded JSON bytes
 * @returns {any} - Canonical form of the deserialized value
 */
export function deserialize(bytes) {
  const json = new TextDecoder().decode(bytes);
  const value = JSON.parse(json);
  return canonicalize(value);
}

/**
 * Compute SHA-256 hash of canonical bytes.
 * @param {any} value - Value to hash (will be canonicalized)
 * @returns {Promise<string>} - Lowercase hex hash
 */
export async function hashCanonical(value) {
  const canonical = canonicalize(value);
  const bytes = serialize(canonical);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Check if two values are canonical-equivalent.
 * @param {any} a - First value
 * @param {any} b - Second value
 * @returns {boolean}
 */
export function canonicalEqual(a, b) {
  const ca = canonicalize(a);
  const cb = canonicalize(b);
  return JSON.stringify(ca) === JSON.stringify(cb);
}

/**
 * Sentinel value for representing "absent" in contexts where
 * null and absent must be distinguished (e.g., patch hashing).
 */
export const ABSENT = Symbol.for('flowversion.absent');

/**
 * Hash a value that might be absent.
 * @param {any} value - Value or ABSENT symbol
 * @returns {Promise<string>} - Hash or special absent marker
 */
export async function hashValueOrAbsent(value) {
  if (value === ABSENT) {
    // Hash a sentinel object for absent values
    return await hashCanonical({ __fv_absent: true });
  }
  return await hashCanonical(value);
}

// Export for testing
export const _internal = {
  canonicalizeNumber,
  canonicalizeString,
  canonicalizeArray,
  canonicalizeObject,
  normalizeTimestamp
};
