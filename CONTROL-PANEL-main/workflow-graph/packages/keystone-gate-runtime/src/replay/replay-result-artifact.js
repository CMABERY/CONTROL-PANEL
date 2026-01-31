/**
 * Replay Result Artifacts (Phase 5)
 *
 * Replay results are NOT envelope records and must not introduce new envelope schemas.
 * They are content-addressed JSON artifacts stored in the ledger.
 */

import { canonicalizeEnvelope, hashEnvelope } from '../flowversion-envelope.js';

/**
 * @typedef {'forensic'|'constrained'|'invariant'} ReplayType
 */

/**
 * @typedef {'pass'|'fail'} ReplayOutcome
 */

/**
 * Replay result record (not a new envelope schema).
 *
 * Required fields are the minimum contract for storage, provenance, and audit.
 * Implementations may attach additional diagnostic fields, but they must remain
 * JSON-serializable and deterministic for a fixed input.
 *
 * @typedef {Object} ReplayResultRecord
 * @property {ReplayType} replay_type
 * @property {string} target_trace_id
 * @property {string[]} input_envelope_hashes
 * @property {ReplayOutcome} result
 * @property {string=} failure_class
 * @property {string} generated_at
 */

/**
 * Canonicalize and hash a replay result record.
 *
 * @param {ReplayResultRecord} result
 * @returns {{ canonical_json: string, sha256: string }}
 */
export function sealReplayResult(result) {
  const canonical_json = canonicalizeEnvelope(result);
  const sha256 = hashEnvelope(result);
  return { canonical_json, sha256 };
}

/**
 * Persist the replay result artifact into a generic ledger bucket.
 *
 * This function does not mutate envelope artifacts.
 *
 * @param {any} store ArtifactStore-compatible object
 * @param {ReplayResultRecord} result
 * @returns {{ artifact_sha256: string, canonical_json: string }}
 */
export function persistReplayResult(store, result) {
  const { canonical_json, sha256 } = sealReplayResult(result);

  // Attach a generic artifacts map if not present.
  if (!store.other_artifacts) {
    // non-enumerable to reduce risk of accidental canonicalization drift elsewhere
    Object.defineProperty(store, 'other_artifacts', {
      value: new Map(),
      writable: false,
      enumerable: false,
      configurable: false,
    });
  }

  // @ts-ignore
  store.other_artifacts.set(sha256, {
    artifact_sha256: sha256,
    canonical_json,
    artifact: result,
    artifact_type: 'replay_result',
  });

  return { artifact_sha256: sha256, canonical_json };
}

/**
 * Create a deterministic ISO-8601 timestamp string from a provided Date.
 *
 * Replay tests provide a fixed clock value to preserve determinism.
 *
 * @param {Date} d
 */
export function isoTime(d) {
  return d.toISOString();
}
