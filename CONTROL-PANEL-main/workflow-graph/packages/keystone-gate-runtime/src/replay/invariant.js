/**
 * Invariant Replay Engine (Phase 5)
 *
 * No execution.
 * Verifies:
 * - schema validity
 * - hash integrity (re-hash)
 * - prerequisite existence
 * - trace continuity
 * - authorization correctness (policy allow required for evidence)
 */

import { ReplayIndex } from './replay-index.js';
import { validateEnvelope, hashEnvelope } from '../flowversion-envelope.js';
import { buildReplayResult, persistReplayResult } from './replay-result.js';
import { FailureClass } from '../error-classification.js';

function nowMs() {
  return Date.now();
}

function traceId(envelope) {
  return envelope?.trace?.trace_id;
}

function firstFailure(ref, failure_class, failure_kind, extra = {}) {
  return {
    classification: failure_class,
    failure_kind,
    at: {
      status: ref?.status ?? null,
      record_type: ref?.record_type ?? null,
      envelope_hash: ref?.envelope_hash ?? null,
    },
    ...extra,
  };
}

/**
 * Invariant replay over accepted artifacts for a trace_id.
 *
 * @param {object} args
 * @param {any} args.ledger
 * @param {string} args.trace_id
 * @param {boolean} [args.emit_result]
 */
export function invariantReplay(args) {
  const { ledger, trace_id, emit_result = true } = args;
  const idx = ReplayIndex.fromLedger(ledger);
  const resolved = idx.resolve(trace_id);

  if (resolved.accepted.length === 0) {
    const replay_result = buildReplayResult({
      replay_type: 'invariant',
      target_trace_id: trace_id,
      input_envelope_hashes: [],
      result: 'fail',
      failure_class: 'REPLAY_NOT_FOUND',
      failure_kind: 'replay.not_found',
      generated_at_ms: nowMs(),
      details: {},
    });
    const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
    return { ok: false, replay_result, result_artifact };
  }

  // Envelope-level invariants
  for (const ref of resolved.accepted) {
    const v = validateEnvelope(ref.envelope);
    if (!v.ok) {
      const replay_result = buildReplayResult({
        replay_type: 'invariant',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.SCHEMA_REJECT,
        failure_kind: 'replay.schema_reject',
        generated_at_ms: nowMs(),
        details: firstFailure(ref, FailureClass.SCHEMA_REJECT, 'replay.schema_reject', { schema_errors: v.errors }),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }

    // All artifacts in a trace replay must have the requested trace_id.
    if (traceId(ref.envelope) !== trace_id) {
      const replay_result = buildReplayResult({
        replay_type: 'invariant',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.TRACE_VIOLATION,
        failure_kind: 'replay.trace_id_mismatch',
        generated_at_ms: nowMs(),
        details: firstFailure(ref, FailureClass.TRACE_VIOLATION, 'replay.trace_id_mismatch'),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }

    const recomputed = hashEnvelope(ref.envelope);
    if (recomputed !== ref.envelope_hash) {
      const replay_result = buildReplayResult({
        replay_type: 'invariant',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        failure_kind: 'replay.hash_integrity_mismatch',
        generated_at_ms: nowMs(),
        details: firstFailure(ref, FailureClass.HASH_MISMATCH, 'replay.hash_integrity_mismatch', {
          expected_envelope_hash: ref.envelope_hash,
          recomputed_envelope_hash: recomputed,
        }),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }
  }

  // Chain-level invariants (prereqs / trace continuity / authorization).
  for (const ref of resolved.accepted) {
    const e = ref.envelope;
    if (ref.record_type === 'policy_decision') {
      const authHash = e.auth_context_envelope_sha256;
      const auth = ledger.getAccepted(authHash);
      if (!auth) {
        const replay_result = buildReplayResult({
          replay_type: 'invariant',
          target_trace_id: trace_id,
          input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
          result: 'fail',
          failure_class: FailureClass.MISSING_PREREQ,
          failure_kind: 'missing_prereq.auth_context',
          generated_at_ms: nowMs(),
          details: firstFailure(ref, FailureClass.MISSING_PREREQ, 'missing_prereq.auth_context', { missing: authHash }),
        });
        const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
        return { ok: false, replay_result, result_artifact };
      }
      if (traceId(auth.envelope) !== trace_id) {
        const replay_result = buildReplayResult({
          replay_type: 'invariant',
          target_trace_id: trace_id,
          input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
          result: 'fail',
          failure_class: FailureClass.TRACE_VIOLATION,
          failure_kind: 'trace_violation.trace_id_mismatch',
          generated_at_ms: nowMs(),
          details: firstFailure(ref, FailureClass.TRACE_VIOLATION, 'trace_violation.trace_id_mismatch'),
        });
        const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
        return { ok: false, replay_result, result_artifact };
      }
    }

    if (ref.record_type === 'model_call' || ref.record_type === 'tool_call') {
      const authHash = e.auth_context_envelope_sha256;
      const policyHash = e.policy_decision_envelope_sha256;

      const auth = ledger.getAccepted(authHash);
      if (!auth) {
        const replay_result = buildReplayResult({
          replay_type: 'invariant',
          target_trace_id: trace_id,
          input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
          result: 'fail',
          failure_class: FailureClass.MISSING_PREREQ,
          failure_kind: 'missing_prereq.auth_context',
          generated_at_ms: nowMs(),
          details: firstFailure(ref, FailureClass.MISSING_PREREQ, 'missing_prereq.auth_context', { missing: authHash }),
        });
        const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
        return { ok: false, replay_result, result_artifact };
      }

      const policy = ledger.getAccepted(policyHash);
      if (!policy) {
        const replay_result = buildReplayResult({
          replay_type: 'invariant',
          target_trace_id: trace_id,
          input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
          result: 'fail',
          failure_class: FailureClass.MISSING_PREREQ,
          failure_kind: 'missing_prereq.policy_decision',
          generated_at_ms: nowMs(),
          details: firstFailure(ref, FailureClass.MISSING_PREREQ, 'missing_prereq.policy_decision', { missing: policyHash }),
        });
        const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
        return { ok: false, replay_result, result_artifact };
      }

      if (traceId(auth.envelope) !== trace_id || traceId(policy.envelope) !== trace_id) {
        const replay_result = buildReplayResult({
          replay_type: 'invariant',
          target_trace_id: trace_id,
          input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
          result: 'fail',
          failure_class: FailureClass.TRACE_VIOLATION,
          failure_kind: 'trace_violation.trace_id_mismatch',
          generated_at_ms: nowMs(),
          details: firstFailure(ref, FailureClass.TRACE_VIOLATION, 'trace_violation.trace_id_mismatch'),
        });
        const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
        return { ok: false, replay_result, result_artifact };
      }

      const decision = policy.envelope?.decision?.result;
      if (decision !== 'allow') {
        const replay_result = buildReplayResult({
          replay_type: 'invariant',
          target_trace_id: trace_id,
          input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
          result: 'fail',
          failure_class: FailureClass.UNAUTHORIZED_EXECUTION,
          failure_kind: 'unauthorized_execution.policy_denied',
          generated_at_ms: nowMs(),
          details: firstFailure(ref, FailureClass.UNAUTHORIZED_EXECUTION, 'unauthorized_execution.policy_denied'),
        });
        const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
        return { ok: false, replay_result, result_artifact };
      }
    }
  }

  const replay_result = buildReplayResult({
    replay_type: 'invariant',
    target_trace_id: trace_id,
    input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
    result: 'pass',
    failure_class: null,
    failure_kind: null,
    generated_at_ms: nowMs(),
    details: {
      accepted_count: resolved.accepted.length,
      rejected_attempts_observed: resolved.rejected_attempts.length,
    },
  });

  const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
  return { ok: true, replay_result, result_artifact };
}
