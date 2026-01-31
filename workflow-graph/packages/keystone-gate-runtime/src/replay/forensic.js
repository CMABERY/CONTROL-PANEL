/**
 * Forensic Replay Engine (Phase 5)
 *
 * Bit-exact verification:
 * - schema re-validation
 * - RFC8785/JCS canonicalization re-run
 * - SHA-256 hash re-run
 * - canonical JSON must match stored canonical bytes
 * - computed hash must match stored envelope_hash
 * - prerequisites / trace continuity / authorization are re-checked via re-ingestion
 */

import { CpoKernel } from '../cpo-kernel.js';
import { ReplayIndex } from './replay-index.js';
import { Ledger } from './ledger.js';
import { canonicalizeEnvelope, hashEnvelope, validateEnvelope } from '../flowversion-envelope.js';
import { buildReplayResult, persistReplayResult } from './replay-result.js';
import { FailureClass } from '../error-classification.js';

function nowMs() {
  return Date.now();
}

function firstFailureDetails(ref, classification, failure_kind, extra = {}) {
  return {
    classification,
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
 * Forensic replay over accepted artifacts for a trace_id.
 *
 * @param {object} args
 * @param {any} args.ledger
 * @param {string} args.trace_id
 * @param {boolean} [args.emit_result]
 * @returns {{ok: boolean, result_artifact?: {artifact_hash: string, canonical_json: string, artifact: any}, replay_result: any}}
 */
export function forensicReplay(args) {
  const { ledger, trace_id, emit_result = true } = args;

  const idx = ReplayIndex.fromLedger(ledger);
  const resolved = idx.resolve(trace_id);

  if (resolved.accepted.length === 0) {
    const replay_result = buildReplayResult({
      replay_type: 'forensic',
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

  // Re-ingest accepted artifacts into a fresh kernel to re-run prereq/trace/authz checks.
  const simulationLedger = new Ledger();
  const kernel = new CpoKernel(simulationLedger);

  for (const ref of resolved.accepted) {
    // 0) Schema re-validation is explicit in forensic mode.
    const v = validateEnvelope(ref.envelope);
    if (!v.ok) {
      const replay_result = buildReplayResult({
        replay_type: 'forensic',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.SCHEMA_REJECT,
        failure_kind: 'replay.schema_reject',
        generated_at_ms: nowMs(),
        details: firstFailureDetails(ref, FailureClass.SCHEMA_REJECT, 'replay.schema_reject', { schema_errors: v.errors }),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }

    // 1) Canonical bytes match stored canonical JSON.
    const recomputed_canonical = canonicalizeEnvelope(ref.envelope);
    if (typeof ref.canonical_json === 'string' && recomputed_canonical !== ref.canonical_json) {
      const replay_result = buildReplayResult({
        replay_type: 'forensic',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        failure_kind: 'replay.canonical_json_mismatch',
        generated_at_ms: nowMs(),
        details: firstFailureDetails(ref, FailureClass.HASH_MISMATCH, 'replay.canonical_json_mismatch'),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }

    // 2) Hash integrity.
    const recomputed_hash = hashEnvelope(ref.envelope);
    if (recomputed_hash !== ref.envelope_hash) {
      const replay_result = buildReplayResult({
        replay_type: 'forensic',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        failure_kind: 'replay.hash_integrity_mismatch',
        generated_at_ms: nowMs(),
        details: firstFailureDetails(ref, FailureClass.HASH_MISMATCH, 'replay.hash_integrity_mismatch', {
          expected_envelope_hash: ref.envelope_hash,
          recomputed_envelope_hash: recomputed_hash,
        }),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }

    // 3) Re-ingest through commit_action to re-check prereqs/trace/authz.
    const r = kernel.commit_action(ref.record_type, ref.envelope_hash, ref.envelope);
    if (!r.ok) {
      const replay_result = buildReplayResult({
        replay_type: 'forensic',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((rr) => rr.envelope_hash),
        result: 'fail',
        failure_class: r.classification,
        failure_kind: r.error_kind ?? 'replay.commit_action_reject',
        generated_at_ms: nowMs(),
        details: firstFailureDetails(ref, r.classification, r.error_kind ?? 'replay.commit_action_reject'),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }

    // 4) Canonical JSON produced during re-ingestion must match stored canonical JSON.
    if (typeof ref.canonical_json === 'string' && r.canonical_json !== ref.canonical_json) {
      const replay_result = buildReplayResult({
        replay_type: 'forensic',
        target_trace_id: trace_id,
        input_envelope_hashes: resolved.accepted.map((rr) => rr.envelope_hash),
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        failure_kind: 'replay.canonical_json_mismatch_commit',
        generated_at_ms: nowMs(),
        details: firstFailureDetails(ref, FailureClass.HASH_MISMATCH, 'replay.canonical_json_mismatch_commit'),
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }
  }

  const replay_result = buildReplayResult({
    replay_type: 'forensic',
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
