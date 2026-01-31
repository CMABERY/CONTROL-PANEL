/**
 * Constrained Replay Engine (Phase 5)
 *
 * Verifies policy-path equivalence between two traces while allowing bounded
 * nondeterminism (e.g., model/tool responses).
 *
 * Constrained replay DOES NOT execute tools/models.
 */

import { ReplayIndex } from './replay-index.js';
import { invariantReplay } from './invariant.js';
import { canonicalizeEnvelope, hashEnvelope } from '../flowversion-envelope.js';
import { buildReplayResult, persistReplayResult } from './replay-result.js';

function nowMs() {
  return Date.now();
}

/**
 * @typedef {Object} ConstrainedReplayPolicy
 * @property {Record<string, string[]>} vary
 *   Map record_type -> list of top-level fields allowed to vary.
 *   Example: { model_call: ['response', 'usage'], tool_call: ['response'] }
 * @property {boolean} require_same_evidence_shape
 *   When true, evidence "intent" signatures (tool_name/model identifiers + request BlobRef) must match.
 */

function stableStringify(obj) {
  return canonicalizeEnvelope(obj);
}

function recordTypeSet(chain) {
  const s = new Set();
  for (const r of chain) s.add(r.record_type);
  return s;
}

function policyDecisionSignature(pdEnvelope) {
  return {
    policy_id: pdEnvelope.policy?.policy_id ?? null,
    policy_version: pdEnvelope.policy?.policy_version ?? null,
    policy_sha256: pdEnvelope.policy?.policy_sha256 ?? null,
    action: pdEnvelope.request?.action ?? null,
    resource: pdEnvelope.request?.resource ?? null,
    decision_result: pdEnvelope.decision?.result ?? null,
    reason_codes: pdEnvelope.decision?.reason_codes ?? {},
    obligations: pdEnvelope.decision?.obligations ?? {},
  };
}

function evidenceIntentSignature(ref) {
  const e = ref.envelope;
  if (ref.record_type === 'model_call') {
    return {
      record_type: 'model_call',
      model_provider: e.model?.provider ?? null,
      model: e.model?.model ?? null,
      request: e.request ?? null,
      outcome_status: e.outcome?.status ?? null,
    };
  }
  if (ref.record_type === 'tool_call') {
    return {
      record_type: 'tool_call',
      adapter_id: e.tool?.adapter_id ?? null,
      tool_name: e.tool?.tool_name ?? null,
      request: e.request ?? null,
      outcome_status: e.outcome?.status ?? null,
    };
  }
  return { record_type: ref.record_type };
}

function projectForEquivalence(ref, policy) {
  // Remove volatile / per-run fields and allowed-to-vary fields.
  const e = structuredClone(ref.envelope);
  delete e.trace;
  delete e.ts_ms;
  delete e.started_at_ms;
  delete e.ended_at_ms;
  delete e.producer;
  delete e.auth_context_envelope_sha256;
  delete e.policy_decision_envelope_sha256;

  const varyFields = policy.vary?.[ref.record_type] ?? [];
  for (const f of varyFields) {
    delete e[f];
  }

  return e;
}

function equivalenceHash(ref, policy) {
  const projected = projectForEquivalence(ref, policy);
  const canonical = stableStringify(projected);
  const hash = hashEnvelope(projected);
  return { canonical, hash, projected };
}

/**
 * Constrained replay compares two traces:
 * - baseline_trace_id: original run
 * - candidate_trace_id: replay run
 *
 * @param {object} args
 * @param {any} args.ledger
 * @param {string} args.baseline_trace_id
 * @param {string} args.candidate_trace_id
 * @param {ConstrainedReplayPolicy} args.policy
 * @param {boolean} [args.emit_result]
 */
export function constrainedReplay(args) {
  const { ledger, baseline_trace_id, candidate_trace_id, policy, emit_result = true } = args;

  // 0) Both traces must be internally invariant-valid.
  const invBase = invariantReplay({ ledger, trace_id: baseline_trace_id, emit_result: false });
  if (!invBase.ok) {
    const replay_result = buildReplayResult({
      replay_type: 'constrained',
      target_trace_id: candidate_trace_id,
      input_envelope_hashes: invBase.replay_result?.input_envelope_hashes ?? [],
      result: 'fail',
      failure_class: invBase.replay_result?.failure_class ?? 'REPLAY_BASELINE_INVALID',
      failure_kind: 'replay.baseline_invariant_fail',
      generated_at_ms: nowMs(),
      details: { baseline_trace_id, candidate_trace_id, baseline_failure: invBase.replay_result },
    });
    const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
    return { ok: false, replay_result, result_artifact };
  }

  const invCand = invariantReplay({ ledger, trace_id: candidate_trace_id, emit_result: false });
  if (!invCand.ok) {
    const replay_result = buildReplayResult({
      replay_type: 'constrained',
      target_trace_id: candidate_trace_id,
      input_envelope_hashes: invCand.replay_result?.input_envelope_hashes ?? [],
      result: 'fail',
      failure_class: invCand.replay_result?.failure_class ?? 'REPLAY_CANDIDATE_INVALID',
      failure_kind: 'replay.candidate_invariant_fail',
      generated_at_ms: nowMs(),
      details: { baseline_trace_id, candidate_trace_id, candidate_failure: invCand.replay_result },
    });
    const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
    return { ok: false, replay_result, result_artifact };
  }

  const idx = ReplayIndex.fromLedger(ledger);
  const base = idx.resolve(baseline_trace_id).accepted;
  const cand = idx.resolve(candidate_trace_id).accepted;

  // 1) Policy-path equivalence (PolicyDecisionRecord signatures must match as a multiset).
  const basePD = base.filter((r) => r.record_type === 'policy_decision').map((r) => policyDecisionSignature(r.envelope));
  const candPD = cand.filter((r) => r.record_type === 'policy_decision').map((r) => policyDecisionSignature(r.envelope));

  const sortSig = (a, b) => {
    const ka = `${a.action}|${a.resource}|${a.policy_sha256}|${a.decision_result}`;
    const kb = `${b.action}|${b.resource}|${b.policy_sha256}|${b.decision_result}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  };
  basePD.sort(sortSig);
  candPD.sort(sortSig);

  const basePDJson = stableStringify(basePD);
  const candPDJson = stableStringify(candPD);
  if (basePDJson !== candPDJson) {
    const replay_result = buildReplayResult({
      replay_type: 'constrained',
      target_trace_id: candidate_trace_id,
      input_envelope_hashes: cand.map((r) => r.envelope_hash),
      result: 'fail',
      failure_class: 'REPLAY_POLICY_MISMATCH',
      failure_kind: 'replay.policy_path_mismatch',
      generated_at_ms: nowMs(),
      details: {
        baseline_trace_id,
        candidate_trace_id,
        baseline_policy_path: basePD,
        candidate_policy_path: candPD,
      },
    });
    const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
    return { ok: false, replay_result, result_artifact };
  }

  // 2) Evidence shape equivalence (optional): same "intent" multiset.
  if (policy.require_same_evidence_shape) {
    const baseEv = base.filter((r) => r.record_type === 'model_call' || r.record_type === 'tool_call').map(evidenceIntentSignature);
    const candEv = cand.filter((r) => r.record_type === 'model_call' || r.record_type === 'tool_call').map(evidenceIntentSignature);

    const sortEv = (a, b) => {
      const ka = stableStringify(a);
      const kb = stableStringify(b);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    };
    baseEv.sort(sortEv);
    candEv.sort(sortEv);

    if (stableStringify(baseEv) !== stableStringify(candEv)) {
      const replay_result = buildReplayResult({
        replay_type: 'constrained',
        target_trace_id: candidate_trace_id,
        input_envelope_hashes: cand.map((r) => r.envelope_hash),
        result: 'fail',
        failure_class: 'REPLAY_EVIDENCE_SHAPE_MISMATCH',
        failure_kind: 'replay.evidence_shape_mismatch',
        generated_at_ms: nowMs(),
        details: { baseline_trace_id, candidate_trace_id, baseline_evidence: baseEv, candidate_evidence: candEv },
      });
      const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
      return { ok: false, replay_result, result_artifact };
    }
  }

  // 3) Variance bounds: differences must be explainable only by allowed vary-fields.
  const baseEq = base.map((r) => ({ record_type: r.record_type, ...equivalenceHash(r, policy) })).sort((a, b) => {
    const ka = `${a.record_type}|${a.hash}`;
    const kb = `${b.record_type}|${b.hash}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const candEq = cand.map((r) => ({ record_type: r.record_type, ...equivalenceHash(r, policy) })).sort((a, b) => {
    const ka = `${a.record_type}|${a.hash}`;
    const kb = `${b.record_type}|${b.hash}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  if (stableStringify(baseEq.map((x) => ({ record_type: x.record_type, hash: x.hash }))) !== stableStringify(candEq.map((x) => ({ record_type: x.record_type, hash: x.hash })))) {
    const replay_result = buildReplayResult({
      replay_type: 'constrained',
      target_trace_id: candidate_trace_id,
      input_envelope_hashes: cand.map((r) => r.envelope_hash),
      result: 'fail',
      failure_class: 'REPLAY_VARIANCE_NOT_ALLOWED',
      failure_kind: 'replay.variance_bounds_exceeded',
      generated_at_ms: nowMs(),
      details: {
        baseline_trace_id,
        candidate_trace_id,
        policy,
        baseline_equivalence: baseEq.map((x) => ({ record_type: x.record_type, hash: x.hash })),
        candidate_equivalence: candEq.map((x) => ({ record_type: x.record_type, hash: x.hash })),
      },
    });
    const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
    return { ok: false, replay_result, result_artifact };
  }

  // Report which envelope hashes differ (expected for allowed-vary fields and trace/time changes).
  const baseHashes = base.map((r) => ({ record_type: r.record_type, envelope_hash: r.envelope_hash }));
  const candHashes = cand.map((r) => ({ record_type: r.record_type, envelope_hash: r.envelope_hash }));

  const replay_result = buildReplayResult({
    replay_type: 'constrained',
    target_trace_id: candidate_trace_id,
    input_envelope_hashes: cand.map((r) => r.envelope_hash),
    result: 'pass',
    failure_class: null,
    failure_kind: null,
    generated_at_ms: nowMs(),
    details: {
      baseline_trace_id,
      candidate_trace_id,
      policy,
      baseline_record_types: Array.from(recordTypeSet(base)),
      candidate_record_types: Array.from(recordTypeSet(cand)),
      baseline_envelope_hashes: baseHashes,
      candidate_envelope_hashes: candHashes,
      allowed_vary_fields: policy.vary,
      note: 'envelope_hash values are expected to differ across traces; equivalence is evaluated on policy-path + constrained projections',
    },
  });

  const result_artifact = emit_result ? persistReplayResult(ledger, replay_result) : undefined;
  return { ok: true, replay_result, result_artifact };
}
