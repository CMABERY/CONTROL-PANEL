// LOCKED (archival): superseded by canonical implementations under ./replay/
//
// Retained for historical continuity only.
// Do not use for new development. Reference ./replay/*.js as canonical.

/**
 * Phase 5: Replay Result Artifacts
 *
 * Replay results are NOT envelope records (no Phase 1 schema). They are still
 * ledger artifacts:
 *   replay_result_sha256 := sha256(canonical_json_utf8(result_record))
 *
 * Determinism:
 * - Canonicalization uses the same RFC 8785 / JCS implementation used for
 *   envelope hashing.
 */

import { canonicalizeEnvelope } from './flowversion-envelope.js';
import { createHash } from 'node:crypto';

/**
 * @typedef {'forensic'|'constrained'|'invariant'} ReplayType
 */

/**
 * Minimal replay result record (contract per Phase 5).
 *
 * @typedef {Object} ReplayResultRecord
 * @property {ReplayType} replay_type
 * @property {string} target_trace_id
 * @property {any} input_envelope_hashes
 * @property {'pass'|'fail'} result
 * @property {string=} failure_class
 * @property {number} generated_at
 */

/**
 * sha256 hex over UTF-8 bytes.
 * @param {string} s
 */
function sha256HexUtf8(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/**
 * Canonicalize + hash a replay result record, returning the content address.
 *
 * @param {ReplayResultRecord} record
 * @returns {{ artifact_hash: string, canonical_json: string }}
 */
export function hashReplayResult(record) {
  const canonical_json = canonicalizeEnvelope(record);
  const artifact_hash = sha256HexUtf8(canonical_json);
  return { artifact_hash, canonical_json };
}

/**
 * Store a replay result as a ledger artifact.
 *
 * IMPORTANT: This bypasses commit_action because replay results are not
 * Phase 1 envelope records.
 *
 * @param {{ putReplayResult: (artifact_hash: string, record: any) => void }} store
 * @param {ReplayResultRecord} record
 * @returns {{ artifact_hash: string, canonical_json: string, record: ReplayResultRecord }}
 */
export function emitReplayResult(store, record) {
  const { artifact_hash, canonical_json } = hashReplayResult(record);
  store.putReplayResult(artifact_hash, {
    artifact_kind: 'replay_result',
    artifact_hash,
    canonical_json,
    record,
  });
  return { artifact_hash, canonical_json, record };
}
