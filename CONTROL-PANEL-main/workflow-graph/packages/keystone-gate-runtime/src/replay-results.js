// LOCKED (archival): superseded by canonical implementations under ./replay/
//
// Retained for historical continuity only.
// Do not use for new development. Reference ./replay/*.js as canonical.

/**
 * Phase 5: Replay Result Artifacts (not an envelope schema)
 *
 * Replay results are content-addressed ledger artifacts:
 *   replay_result_sha256 := sha256( canonical_json_utf8(result_record) )
 *
 * Canonicalization is RFC 8785 / JCS via FlowVersion canonicalizeEnvelope().
 */

import { canonicalizeEnvelope, hashEnvelope } from './flowversion-envelope.js';

/**
 * @typedef {'forensic'|'constrained'|'invariant'} ReplayType
 */

/**
 * @typedef {'pass'|'fail'} ReplayOutcome
 */

/**
 * @typedef {Object} ReplayResultRecord
 * @property {ReplayType} replay_type
 * @property {string} target_trace_id
 * @property {string[]} input_envelope_hashes
 * @property {ReplayOutcome} result
 * @property {string|null} failure_class
 * @property {string} generated_at
 * @property {any=} details
 */

/**
 * Build a replay result record (closed-world by construction; no runtime schema).
 *
 * @param {ReplayResultRecord} r
 * @returns {ReplayResultRecord}
 */
export function buildReplayResult(r) {
  if (!r || typeof r !== 'object') throw new Error('replay result must be an object');

  // Required fields must exist; fail-closed.
  const required = ['replay_type', 'target_trace_id', 'input_envelope_hashes', 'result', 'failure_class', 'generated_at'];
  for (const k of required) {
    if (!(k in r)) throw new Error(`missing replay result field: ${k}`);
  }

  // Defensive copies for determinism.
  const hashes = [...r.input_envelope_hashes].sort();

  return {
    replay_type: r.replay_type,
    target_trace_id: r.target_trace_id,
    input_envelope_hashes: hashes,
    result: r.result,
    failure_class: r.failure_class,
    generated_at: r.generated_at,
    ...(r.details ? { details: r.details } : {}),
  };
}

/**
 * Canonical JSON for a replay result record.
 *
 * @param {ReplayResultRecord} record
 * @returns {string}
 */
export function canonicalizeReplayResult(record) {
  return canonicalizeEnvelope(record);
}

/**
 * Content-address the replay result.
 *
 * @param {ReplayResultRecord} record
 * @returns {{ replay_result_sha256: string, canonical_json: string }}
 */
export function hashReplayResult(record) {
  const canonical_json = canonicalizeReplayResult(record);
  const replay_result_sha256 = hashEnvelope(record);
  return { replay_result_sha256, canonical_json };
}

/**
 * In-memory ledger namespace for replay results.
 */
export class ReplayResultStore {
  constructor() {
    /** @type {Map<string, { canonical_json: string, record: any }>} */
    this.results = new Map();
  }

  put(replay_result_sha256, canonical_json, record) {
    this.results.set(replay_result_sha256, { canonical_json, record });
  }

  get(replay_result_sha256) {
    return this.results.get(replay_result_sha256);
  }
}
