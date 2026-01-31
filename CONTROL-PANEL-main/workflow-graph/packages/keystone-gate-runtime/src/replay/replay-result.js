/**
 * Replay Result Artifact (Phase 5)
 *
 * Not a new envelope schema.
 * Stored as a content-addressed ledger artifact:
 *   sha256( canonical_json_utf8(result) )
 */

import { canonicalizeEnvelope, hashEnvelope } from '../flowversion-envelope.js';

/**
 * @typedef {'forensic'|'constrained'|'invariant'} ReplayType
 * @typedef {'pass'|'fail'} ReplayOutcome
 */

/**
 * Minimal required shape per Phase 5:
 * - replay_type
 * - target_trace_id
 * - input_envelope_hashes
 * - result
 * - failure_class (if any)
 * - generated_at_ms
 */

/**
 * @param {any} result
 * @returns {string}
 */
export function canonicalizeReplayResult(result) {
  return canonicalizeEnvelope(result);
}

/**
 * @param {any} result
 * @returns {string}
 */
export function hashReplayResult(result) {
  return hashEnvelope(result);
}

/**
 * @param {object} args
 * @param {ReplayType} args.replay_type
 * @param {string} args.target_trace_id
 * @param {string[]} args.input_envelope_hashes
 * @param {ReplayOutcome} args.result
 * @param {string|null} [args.failure_class]
 * @param {string|null} [args.failure_kind]
 * @param {number} args.generated_at_ms
 * @param {object} [args.details]
 */
export function buildReplayResult(args) {
  return {
    replay_type: args.replay_type,
    target_trace_id: args.target_trace_id,
    input_envelope_hashes: args.input_envelope_hashes,
    result: args.result,
    failure_class: args.failure_class ?? null,
    failure_kind: args.failure_kind ?? null,
    generated_at_ms: args.generated_at_ms,
    details: args.details ?? {},
  };
}

/**
 * Content-address and store a replay result artifact.
 *
 * @param {any} ledger - must implement putReplayResult(hash, canonical_json, artifact)
 * @param {any} result
 * @returns {{artifact_hash: string, canonical_json: string, artifact: any}}
 */
export function persistReplayResult(ledger, result) {
  const canonical_json = canonicalizeReplayResult(result);
  const artifact_hash = hashReplayResult(result);
  ledger.putReplayResult(artifact_hash, canonical_json, result);
  return { artifact_hash, canonical_json, artifact: result };
}
