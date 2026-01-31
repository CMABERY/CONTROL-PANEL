/**
 * Invariant Replay Engine (Phase 5)
 *
 * No execution. Verifies:
 * - schema validity
 * - hash integrity
 * - prerequisite existence
 * - trace continuity
 * - authorization correctness
 */

import { validateEnvelope, hashEnvelope } from '../flowversion-envelope.js';
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
 * @param {any} envelope
 * @param {string} expectedHash
 * @returns {{ ok: true } | { ok: false, failure_class: string }}
 */
function schemaAndHashCheck(envelope, expectedHash) {
  const v = validateEnvelope(envelope);
  if (!v.ok) return { ok: false, failure_class: ReplayFailure.SCHEMA_REJECT };
  const h = hashEnvelope(envelope);
  if (h !== expectedHash) return { ok: false, failure_class: ReplayFailure.HASH_MISMATCH };
  return { ok: true };
}

/**
 * Run invariant replay over a trace_id.
 *
 * @param {any} store ArtifactStore
 * @param {string} trace_id
 * @param {{ include_rejected_attempts?: boolean, clock?: Date, persist_result?: boolean }} opts
 * @returns {{ record: any, artifact_sha256?: string }}
 */
export function invariantReplay(store, trace_id, opts = {}) {
  const clock = opts.clock || new Date(0);
  const chain = resolveTraceChain(store, trace_id, { include_rejected_attempts: opts.include_rejected_attempts === true });

  /** @type {any} */
  const record = {
    replay_type: 'invariant',
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

  // 1) Schema + hash integrity on each artifact.
  for (const art of chain.ordered) {
    const chk = schemaAndHashCheck(art.envelope, art.envelope_hash);
    if (!chk.ok) {
      record.failure_class = chk.failure_class;
      return finalize(store, record, opts.persist_result !== false);
    }
  }

  // 2) Prereqs + trace continuity + authorization (mirrors commit_action checks).
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
