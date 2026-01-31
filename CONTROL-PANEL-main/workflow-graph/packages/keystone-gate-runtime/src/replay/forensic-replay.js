/**
 * Forensic Replay Engine (Phase 5)
 *
 * Bit-exact verification over ledger artifacts.
 *
 * Requirements:
 * - Re-validate schema for each envelope
 * - Re-canonicalize (RFC 8785/JCS) and assert canonical JSON matches stored bytes
 * - Re-hash and assert computed hash matches stored envelope_hash
 * - Re-run prerequisite resolution, trace continuity, and authorization checks
 */

import { canonicalizeEnvelope, validateEnvelope, hashEnvelope } from '../flowversion-envelope.js';
import { resolveTraceChain } from './replay-index.js';
import { ReplayFailure } from './replay-failure.js';
import { isoTime, persistReplayResult } from './replay-result-artifact.js';

function traceIdOf(envelope) {
  return envelope?.trace?.trace_id;
}

function requireAccepted(store, hash) {
  return store.getAccepted(hash);
}

/**
 * Run forensic replay over a trace_id.
 *
 * @param {any} store ArtifactStore
 * @param {string} trace_id
 * @param {{ include_rejected_attempts?: boolean, clock?: Date, persist_result?: boolean }} opts
 * @returns {{ record: any, artifact_sha256?: string }}
 */
export function forensicReplay(store, trace_id, opts = {}) {
  const clock = opts.clock || new Date(0);
  const chain = resolveTraceChain(store, trace_id, { include_rejected_attempts: opts.include_rejected_attempts === true });

  /** @type {any} */
  const record = {
    replay_type: 'forensic',
    target_trace_id: trace_id,
    input_envelope_hashes: [],
    result: 'fail',
    generated_at: isoTime(clock),
  };

  if (!chain) {
    record.failure_class = ReplayFailure.CHAIN_NOT_FOUND;
    return finalize(store, record, opts.persist_result !== false);
  }

  record.input_envelope_hashes = chain.ordered.map((x) => x.envelope_hash);

  // 1) Schema + canonical bytes + hash integrity on each artifact.
  for (const art of chain.ordered) {
    const v = validateEnvelope(art.envelope);
    if (!v.ok) {
      record.failure_class = ReplayFailure.SCHEMA_REJECT;
      return finalize(store, record, opts.persist_result !== false);
    }

    const canonical = canonicalizeEnvelope(art.envelope);
    if (canonical !== art.canonical_json) {
      record.failure_class = ReplayFailure.HASH_MISMATCH;
      return finalize(store, record, opts.persist_result !== false);
    }

    const h = hashEnvelope(art.envelope);
    if (h !== art.envelope_hash) {
      record.failure_class = ReplayFailure.HASH_MISMATCH;
      return finalize(store, record, opts.persist_result !== false);
    }
  }

  // 2) Prereqs + trace continuity + authorization.
  for (const art of chain.ordered) {
    const rt = art.record_type;
    const env = art.envelope;

    if (rt === 'auth_context') continue;

    if (rt === 'policy_decision') {
      const authHash = env.auth_context_envelope_sha256;
      const auth = requireAccepted(store, authHash);
      if (!auth) {
        record.failure_class = ReplayFailure.MISSING_PREREQ;
        return finalize(store, record, opts.persist_result !== false);
      }
      if (traceIdOf(auth.envelope) !== traceIdOf(env)) {
        record.failure_class = ReplayFailure.TRACE_VIOLATION;
        return finalize(store, record, opts.persist_result !== false);
      }
      continue;
    }

    if (rt === 'model_call' || rt === 'tool_call') {
      const authHash = env.auth_context_envelope_sha256;
      const pdHash = env.policy_decision_envelope_sha256;

      const auth = requireAccepted(store, authHash);
      if (!auth) {
        record.failure_class = ReplayFailure.MISSING_PREREQ;
        return finalize(store, record, opts.persist_result !== false);
      }
      const pd = requireAccepted(store, pdHash);
      if (!pd) {
        record.failure_class = ReplayFailure.MISSING_PREREQ;
        return finalize(store, record, opts.persist_result !== false);
      }

      const tid = traceIdOf(env);
      if (traceIdOf(auth.envelope) !== tid || traceIdOf(pd.envelope) !== tid) {
        record.failure_class = ReplayFailure.TRACE_VIOLATION;
        return finalize(store, record, opts.persist_result !== false);
      }

      const decision = pd.envelope?.decision?.result;
      if (decision !== 'allow') {
        record.failure_class = ReplayFailure.UNAUTHORIZED_EXECUTION;
        return finalize(store, record, opts.persist_result !== false);
      }
      continue;
    }
  }

  record.result = 'pass';
  return finalize(store, record, opts.persist_result !== false);
}

function finalize(store, record, persist) {
  if (persist) {
    const r = persistReplayResult(store, record);
    return { record, artifact_sha256: r.artifact_sha256 };
  }
  return { record };
}
