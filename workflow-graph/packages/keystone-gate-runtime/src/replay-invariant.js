// LOCKED (archival): superseded by canonical implementations under ./replay/
//
// Retained for historical continuity only.
// Do not use for new development. Reference ./replay/*.js as canonical.

/**
 * Phase 5 Replay Plumbing: Invariant Replay (no execution)
 *
 * Invariant replay verifies a trace's accepted evidence chain without executing tools/models.
 * It checks governance invariants only:
 * - schema validity
 * - envelope_hash integrity (re-canonicalize + re-hash)
 * - prerequisite existence (auth + policy)
 * - trace continuity
 * - authorization correctness (policy allow required for tool/model evidence)
 */

import { validateEnvelope, hashEnvelope } from './flowversion-envelope.js';
import { FailureClass } from './error-classification.js';
import { ReplayIndex } from './replay-index.js';
import { emitReplayResult } from './replay-results.js';

function getTraceId(envelope) {
  return envelope?.trace?.trace_id;
}

/**
 * @param {any} store
 * @param {string} trace_id
 * @param {{ now_ms?: number }} opts
 */
export function invariantReplay(store, trace_id, opts = {}) {
  const now_ms = opts.now_ms ?? Date.now();

  const index = new ReplayIndex(store).build();
  const chain = index.resolve(trace_id, { includeRejected: false, order: 'display' });

  /** @type {any} */
  const replayRecordBase = {
    replay_type: 'invariant',
    target_trace_id: trace_id,
    input_envelope_hashes: chain.map((p) => p.envelope_hash),
    generated_at: now_ms,
  };

  if (chain.length === 0) {
    const rec = {
      ...replayRecordBase,
      result: 'fail',
      failure_class: FailureClass.MISSING_PREREQ,
      error_kind: 'replay.not_found',
    };
    const out = emitReplayResult(store, rec);
    return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
  }

  for (const p of chain) {
    // 1) Schema validity.
    const v = validateEnvelope(p.envelope);
    if (!v.ok) {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: FailureClass.SCHEMA_REJECT,
        error_kind: 'replay.schema_invalid_in_ledger',
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }

    // 2) Hash integrity.
    const recomputed = hashEnvelope(p.envelope);
    if (recomputed !== p.envelope_hash) {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        error_kind: 'replay.envelope_hash_mismatch',
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash, recomputed },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }

    // 3) Prereqs + trace + authorization.
    if (p.record_type === 'policy_decision') {
      const authHash = p.envelope.auth_context_envelope_sha256;
      const auth = store.getAccepted(authHash);
      if (!auth) {
        const rec = {
          ...replayRecordBase,
          result: 'fail',
          failure_class: FailureClass.MISSING_PREREQ,
          error_kind: 'missing_prereq.auth_context',
          details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
        };
        const out = emitReplayResult(store, rec);
        return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
      }
      const tSelf = getTraceId(p.envelope);
      const tAuth = getTraceId(auth.envelope);
      if (tSelf !== tAuth) {
        const rec = {
          ...replayRecordBase,
          result: 'fail',
          failure_class: FailureClass.TRACE_VIOLATION,
          error_kind: 'trace_violation.trace_id_mismatch',
          details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
        };
        const out = emitReplayResult(store, rec);
        return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
      }
    }

    if (p.record_type === 'model_call' || p.record_type === 'tool_call') {
      const authHash = p.envelope.auth_context_envelope_sha256;
      const pdHash = p.envelope.policy_decision_envelope_sha256;

      const auth = store.getAccepted(authHash);
      if (!auth) {
        const rec = {
          ...replayRecordBase,
          result: 'fail',
          failure_class: FailureClass.MISSING_PREREQ,
          error_kind: 'missing_prereq.auth_context',
          details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
        };
        const out = emitReplayResult(store, rec);
        return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
      }

      const pd = store.getAccepted(pdHash);
      if (!pd) {
        const rec = {
          ...replayRecordBase,
          result: 'fail',
          failure_class: FailureClass.MISSING_PREREQ,
          error_kind: 'missing_prereq.policy_decision',
          details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
        };
        const out = emitReplayResult(store, rec);
        return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
      }

      const tSelf = getTraceId(p.envelope);
      const tAuth = getTraceId(auth.envelope);
      const tPd = getTraceId(pd.envelope);
      if (tSelf !== tAuth || tSelf !== tPd) {
        const rec = {
          ...replayRecordBase,
          result: 'fail',
          failure_class: FailureClass.TRACE_VIOLATION,
          error_kind: 'trace_violation.trace_id_mismatch',
          details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
        };
        const out = emitReplayResult(store, rec);
        return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
      }

      const decision = pd.envelope?.decision?.result;
      if (decision !== 'allow') {
        const rec = {
          ...replayRecordBase,
          result: 'fail',
          failure_class: FailureClass.UNAUTHORIZED_EXECUTION,
          error_kind: 'unauthorized.policy_denied',
          details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
        };
        const out = emitReplayResult(store, rec);
        return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
      }
    }
  }

  const rec = {
    ...replayRecordBase,
    result: 'pass',
  };
  const out = emitReplayResult(store, rec);
  return { ok: true, ...rec, replay_result_sha256: out.replay_result_sha256 };
}
