/**
 * Constrained Replay Engine (Phase 5)
 *
 * Verifies "policy-path equivalence" between two traces while allowing
 * explicitly-scoped nondeterminism (e.g., ModelCallRecord.response BlobRef).
 *
 * No execution. Operates entirely on persisted ledger artifacts.
 */

import { resolveTraceChain } from './replay-index.js';
import { invariantReplay } from './invariant-replay.js';
import { ReplayFailure } from './replay-failure.js';
import { isoTime, persistReplayResult } from './replay-result-artifact.js';

/**
 * @typedef {Object} ConstrainedReplayPolicy
 * @property {{ model_call?: { allow_response_blobref?: boolean }, tool_call?: { allow_response_blobref?: boolean } }} allow_variance
 */

function keysSorted(obj) {
  if (!obj || typeof obj !== 'object') return [];
  return Object.keys(obj).sort();
}

function policySignature(pdEnv) {
  return {
    policy_id: pdEnv?.policy?.policy_id,
    policy_version: pdEnv?.policy?.policy_version,
    policy_sha256: pdEnv?.policy?.policy_sha256,
    action: pdEnv?.request?.action,
    resource: pdEnv?.request?.resource,
    result: pdEnv?.decision?.result,
    reason_codes: keysSorted(pdEnv?.decision?.reason_codes),
    obligations: keysSorted(pdEnv?.decision?.obligations),
  };
}

function stableJson(x) {
  return JSON.stringify(x);
}

function evidenceIdentity(store, env) {
  const rt = env.record_type;
  if (rt !== 'model_call' && rt !== 'tool_call') return null;

  const pd = store.getAccepted(env.policy_decision_envelope_sha256);
  const pdSig = pd ? policySignature(pd.envelope) : null;

  if (rt === 'model_call') {
    return stableJson({
      rt,
      model: { provider: env?.model?.provider, model: env?.model?.model },
      request: env?.request,
      policy: pdSig,
    });
  }

  return stableJson({
    rt,
    tool: { adapter_id: env?.tool?.adapter_id, tool_name: env?.tool?.tool_name },
    request: env?.request,
    policy: pdSig,
  });
}

function blobrefEquals(a, b) {
  if (a === b) return true;
  if (!a || !b) return false;
  return a.sha256 === b.sha256 && a.size_bytes === b.size_bytes && a.content_type === b.content_type;
}

/**
 * Run constrained replay comparing a baseline trace to a candidate trace.
 *
 * Deterministic rule: both traces must independently pass invariant replay.
 * Then policy-path equivalence is enforced, and allowed variance is applied.
 *
 * @param {any} store ArtifactStore
 * @param {{ baseline_trace_id: string, candidate_trace_id: string, replay_policy: ConstrainedReplayPolicy, clock?: Date, persist_result?: boolean }} args
 * @returns {{ record: any, artifact_sha256?: string, diagnostics?: any }}
 */
export function constrainedReplay(store, args) {
  const clock = args.clock || new Date(0);
  const baseline = resolveTraceChain(store, args.baseline_trace_id);
  const candidate = resolveTraceChain(store, args.candidate_trace_id);

  /** @type {any} */
  const record = {
    replay_type: 'constrained',
    target_trace_id: args.candidate_trace_id,
    input_envelope_hashes: [],
    result: 'fail',
    generated_at: isoTime(clock),
    // additional diagnostics fields (non-schema, content-addressed)
    reference_trace_id: args.baseline_trace_id,
  };

  /** @type {any} */
  const diagnostics = {
    allowed_hash_differences: [],
    baseline_policy_path: null,
    candidate_policy_path: null,
  };

  if (!baseline || !candidate) {
    record.failure_class = ReplayFailure.CHAIN_NOT_FOUND;
    return finalize(store, record, diagnostics, args.persist_result !== false);
  }

  // Union of inputs (baseline then candidate, deterministic ordering).
  record.input_envelope_hashes = [...baseline.ordered.map((x) => x.envelope_hash), ...candidate.ordered.map((x) => x.envelope_hash)];

  // 1) Both traces must satisfy invariant replay.
  const invBase = invariantReplay(store, args.baseline_trace_id, { persist_result: false });
  if (invBase.record.result !== 'pass') {
    record.failure_class = invBase.record.failure_class;
    return finalize(store, record, diagnostics, args.persist_result !== false);
  }
  const invCand = invariantReplay(store, args.candidate_trace_id, { persist_result: false });
  if (invCand.record.result !== 'pass') {
    record.failure_class = invCand.record.failure_class;
    return finalize(store, record, diagnostics, args.persist_result !== false);
  }

  // 2) Policy-path equivalence.
  const basePath = baseline.policy_decision.map((x) => policySignature(x.envelope)).sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  const candPath = candidate.policy_decision.map((x) => policySignature(x.envelope)).sort((a, b) => stableJson(a).localeCompare(stableJson(b)));

  diagnostics.baseline_policy_path = basePath;
  diagnostics.candidate_policy_path = candPath;

  if (basePath.length !== candPath.length) {
    record.failure_class = ReplayFailure.POLICY_PATH_MISMATCH;
    return finalize(store, record, diagnostics, args.persist_result !== false);
  }
  for (let i = 0; i < basePath.length; i++) {
    if (stableJson(basePath[i]) !== stableJson(candPath[i])) {
      record.failure_class = ReplayFailure.POLICY_PATH_MISMATCH;
      return finalize(store, record, diagnostics, args.persist_result !== false);
    }
  }

  // 3) Evidence identity + allowed variance enforcement.
  const baseEvidenceById = new Map();
  for (const art of baseline.evidence) {
    const id = evidenceIdentity(store, art.envelope);
    if (id) baseEvidenceById.set(id, art);
  }
  const candEvidenceById = new Map();
  for (const art of candidate.evidence) {
    const id = evidenceIdentity(store, art.envelope);
    if (id) candEvidenceById.set(id, art);
  }

  // Require same evidence identities (policy-path equivalence at evidence boundary).
  const baseIds = [...baseEvidenceById.keys()].sort();
  const candIds = [...candEvidenceById.keys()].sort();
  if (stableJson(baseIds) !== stableJson(candIds)) {
    record.failure_class = ReplayFailure.POLICY_PATH_MISMATCH;
    return finalize(store, record, diagnostics, args.persist_result !== false);
  }

  // For each matched evidence record, enforce variance policy.
  for (const id of baseIds) {
    const b = baseEvidenceById.get(id);
    const c = candEvidenceById.get(id);
    if (!b || !c) continue;

    const rt = b.record_type;

    // Compare response BlobRef (the only scoped nondeterminism in this phase).
    const bResp = b.envelope?.response;
    const cResp = c.envelope?.response;
    const respEqual = blobrefEquals(bResp, cResp);

    if (!respEqual) {
      const allow = rt === 'model_call'
        ? args.replay_policy?.allow_variance?.model_call?.allow_response_blobref === true
        : args.replay_policy?.allow_variance?.tool_call?.allow_response_blobref === true;

      if (!allow) {
        record.failure_class = ReplayFailure.VARIANCE_VIOLATION;
        return finalize(store, record, diagnostics, args.persist_result !== false);
      }

      diagnostics.allowed_hash_differences.push({
        record_type: rt,
        baseline_envelope_hash: b.envelope_hash,
        candidate_envelope_hash: c.envelope_hash,
        allowed_because: `${rt}.response BlobRef allowed to vary`,
      });
    }
  }

  record.result = 'pass';
  return finalize(store, record, diagnostics, args.persist_result !== false);
}

function finalize(store, record, diagnostics, persist) {
  if (persist) {
    const r = persistReplayResult(store, record);
    return { record, diagnostics, artifact_sha256: r.artifact_sha256 };
  }
  return { record, diagnostics };
}
