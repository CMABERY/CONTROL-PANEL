// LOCKED (archival): superseded by canonical implementations under ./replay/
//
// Retained for historical continuity only.
// Do not use for new development. Reference ./replay/*.js as canonical.

/**
 * Phase 5: Replay Engines (evidence-locked)
 *
 * Implements:
 *  - Forensic replay (bit-exact)
 *  - Constrained replay (policy-path equivalence)
 *  - Invariant replay (no execution)
 *
 * All replay operations are pure functions over ledger artifacts.
 */

import { validateEnvelope, canonicalizeEnvelope, hashEnvelope } from './flowversion-envelope.js';
import { FailureClass } from './error-classification.js';
import { resolveChainByTraceId } from './replay-index.js';

/**
 * @typedef {'forensic'|'constrained'|'invariant'} ReplayType
 */

/**
 * @typedef {Object} ReplayOk
 * @property {true} ok
 * @property {ReplayType} replay_type
 * @property {string} target_trace_id
 * @property {any} input_envelope_hashes
 * @property {'pass'} result
 */

/**
 * @typedef {Object} ReplayFail
 * @property {false} ok
 * @property {ReplayType} replay_type
 * @property {string} target_trace_id
 * @property {any} input_envelope_hashes
 * @property {'fail'} result
 * @property {string} failure_class
 * @property {string} failure_kind
 */

/**
 * @param {string} trace_id
 * @param {any[]} ordered
 */
function envelopeHashes(trace_id, ordered) {
  return ordered.map((e) => e.envelope_hash);
}

/**
 * Common invariant checks used by all replay modes.
 * Returns a failure tuple or null.
 *
 * Checks:
 *  - schema validity
 *  - hash integrity (computed hash equals stored key)
 *  - prereq existence (hash references resolve)
 *  - trace continuity (trace_id matches prereqs)
 *  - authorization for evidence (policy decision == allow)
 *
 * @param {{accepted: Map<string, any>}} store
 * @param {string} trace_id
 * @param {any[]} ordered
 * @returns {{ failure_class: string, failure_kind: string } | null}
 */
function invariantChecks(store, trace_id, ordered) {
  // Absence of evidence is failure.
  if (!ordered || ordered.length === 0) {
    return { failure_class: FailureClass.MISSING_PREREQ, failure_kind: 'replay_missing_trace' };
  }

  // Schema + hash integrity for each envelope.
  for (const entry of ordered) {
    const vr = validateEnvelope(entry.envelope);
    if (!vr.ok) {
      return { failure_class: FailureClass.SCHEMA_REJECT, failure_kind: 'replay_schema_invalid' };
    }

    const computed = hashEnvelope(entry.envelope);
    if (computed !== entry.envelope_hash) {
      return { failure_class: FailureClass.HASH_MISMATCH, failure_kind: 'replay_hash_integrity_mismatch' };
    }

    // Chain trace-id must match requested trace-id.
    if (entry.envelope?.trace?.trace_id !== trace_id) {
      return { failure_class: FailureClass.TRACE_VIOLATION, failure_kind: 'replay_trace_id_mismatch' };
    }
  }

  // Prerequisite resolution + trace continuity + authorization.
  const getAccepted = (h) => store.accepted.get(h) || null;

  for (const entry of ordered) {
    const env = entry.envelope;

    if (entry.record_type === 'policy_decision') {
      const authHash = env.auth_context_envelope_sha256;
      const auth = getAccepted(authHash);
      if (!auth) {
        return { failure_class: FailureClass.MISSING_PREREQ, failure_kind: 'missing_prereq.auth_context' };
      }
      const tSelf = env?.trace?.trace_id;
      const tAuth = auth.envelope?.trace?.trace_id;
      if (tSelf !== tAuth) {
        return { failure_class: FailureClass.TRACE_VIOLATION, failure_kind: 'trace_violation.trace_id_mismatch' };
      }
    }

    if (entry.record_type === 'model_call' || entry.record_type === 'tool_call') {
      const authHash = env.auth_context_envelope_sha256;
      const policyHash = env.policy_decision_envelope_sha256;

      const auth = getAccepted(authHash);
      if (!auth) {
        return { failure_class: FailureClass.MISSING_PREREQ, failure_kind: 'missing_prereq.auth_context' };
      }

      const policy = getAccepted(policyHash);
      if (!policy) {
        return { failure_class: FailureClass.MISSING_PREREQ, failure_kind: 'missing_prereq.policy_decision' };
      }

      const tSelf = env?.trace?.trace_id;
      const tAuth = auth.envelope?.trace?.trace_id;
      const tPolicy = policy.envelope?.trace?.trace_id;
      if (tSelf !== tAuth || tSelf !== tPolicy) {
        return { failure_class: FailureClass.TRACE_VIOLATION, failure_kind: 'trace_violation.trace_id_mismatch' };
      }

      const decision = policy.envelope?.decision?.result;
      if (decision !== 'allow') {
        return { failure_class: FailureClass.UNAUTHORIZED_EXECUTION, failure_kind: 'unauthorized.policy_denied' };
      }
    }
  }

  return null;
}

/**
 * Forensic replay: bit-exact, including canonical JSON byte match.
 *
 * @param {{store: any, trace_id: string}} params
 * @returns {ReplayOk|ReplayFail}
 */
export function forensicReplay(params) {
  const { store, trace_id } = params;
  const { ordered } = resolveChainByTraceId(store, trace_id);

  const input_envelope_hashes = envelopeHashes(trace_id, ordered);

  // First apply invariant checks.
  const inv = invariantChecks(store, trace_id, ordered);
  if (inv) {
    return {
      ok: false,
      replay_type: 'forensic',
      target_trace_id: trace_id,
      input_envelope_hashes,
      result: 'fail',
      failure_class: inv.failure_class,
      failure_kind: inv.failure_kind,
    };
  }

  // Forensic: canonical JSON must match stored canonical bytes.
  for (const entry of ordered) {
    const canon = canonicalizeEnvelope(entry.envelope);
    if (canon !== entry.canonical_json) {
      return {
        ok: false,
        replay_type: 'forensic',
        target_trace_id: trace_id,
        input_envelope_hashes,
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        failure_kind: 'hash_mismatch.canonical_json_mismatch',
      };
    }
  }

  return {
    ok: true,
    replay_type: 'forensic',
    target_trace_id: trace_id,
    input_envelope_hashes,
    result: 'pass',
  };
}

/**
 * Invariant replay: no execution; verifies integrity/invariants but does not
 * require stored canonical JSON strings to match.
 *
 * @param {{store: any, trace_id: string}} params
 * @returns {ReplayOk|ReplayFail}
 */
export function invariantReplay(params) {
  const { store, trace_id } = params;
  const { ordered } = resolveChainByTraceId(store, trace_id);
  const input_envelope_hashes = envelopeHashes(trace_id, ordered);

  const inv = invariantChecks(store, trace_id, ordered);
  if (inv) {
    return {
      ok: false,
      replay_type: 'invariant',
      target_trace_id: trace_id,
      input_envelope_hashes,
      result: 'fail',
      failure_class: inv.failure_class,
      failure_kind: inv.failure_kind,
    };
  }

  return {
    ok: true,
    replay_type: 'invariant',
    target_trace_id: trace_id,
    input_envelope_hashes,
    result: 'pass',
  };
}

/**
 * Constrained replay: compare two traces under an explicit variance policy.
 *
 * This does NOT re-execute tools/models. It compares already-persisted traces.
 *
 * @param {{store: any, baseline_trace_id: string, candidate_trace_id: string, replay_policy: any}} params
 * @returns {ReplayOk|ReplayFail}
 */
export function constrainedReplay(params) {
  const { store, baseline_trace_id, candidate_trace_id, replay_policy } = params;

  const base = resolveChainByTraceId(store, baseline_trace_id);
  const cand = resolveChainByTraceId(store, candidate_trace_id);

  const input_envelope_hashes = {
    baseline: base.ordered.map((e) => e.envelope_hash),
    candidate: cand.ordered.map((e) => e.envelope_hash),
  };

  // Both traces must satisfy invariant replay independently.
  const invBase = invariantChecks(store, baseline_trace_id, base.ordered);
  if (invBase) {
    return {
      ok: false,
      replay_type: 'constrained',
      target_trace_id: baseline_trace_id,
      input_envelope_hashes,
      result: 'fail',
      failure_class: invBase.failure_class,
      failure_kind: `baseline.${invBase.failure_kind}`,
    };
  }
  const invCand = invariantChecks(store, candidate_trace_id, cand.ordered);
  if (invCand) {
    return {
      ok: false,
      replay_type: 'constrained',
      target_trace_id: baseline_trace_id,
      input_envelope_hashes,
      result: 'fail',
      failure_class: invCand.failure_class,
      failure_kind: `candidate.${invCand.failure_kind}`,
    };
  }

  // Policy-path equivalence (referenced policy decisions in evidence order).
  const baseSig = policyPathSignature(store, base.ordered);
  const candSig = policyPathSignature(store, cand.ordered);
  const policy_path_report = {
    baseline_policy_path_sha256: sha256HexUtf8(baseSig),
    candidate_policy_path_sha256: sha256HexUtf8(candSig),
    equal: baseSig === candSig,
  };

  if (!policy_path_report.equal) {
    return {
      ok: false,
      replay_type: 'constrained',
      target_trace_id: baseline_trace_id,
      input_envelope_hashes,
      result: 'fail',
      failure_class: 'POLICY_PATH_MISMATCH',
      failure_kind: 'policy_path_equivalence_failed',
      policy_path_report,
    };
  }

  // Evidence equivalence under explicit variance policy.
  const variance = normalizeReplayPolicy(replay_policy);
  const variance_report = buildVarianceReport(base.ordered, cand.ordered, variance);

  const ev = evidenceEquivalence(store, base.ordered, cand.ordered, variance);
  if (!ev.ok) {
    return {
      ok: false,
      replay_type: 'constrained',
      target_trace_id: baseline_trace_id,
      input_envelope_hashes,
      result: 'fail',
      failure_class: 'EVIDENCE_MISMATCH',
      failure_kind: ev.failure_kind,
      policy_path_report,
      variance_report,
    };
  }

  return {
    ok: true,
    replay_type: 'constrained',
    target_trace_id: baseline_trace_id,
    input_envelope_hashes,
    result: 'pass',
    policy_path_report,
    variance_report,
  };
}

// --------------------------
// Constrained replay helpers
// --------------------------

function normalizeReplayPolicy(policy) {
  const allow = policy?.allow_variance || {};
  return {
    model_call: {
      response: allow?.model_call?.response === true,
      usage: allow?.model_call?.usage === true,
    },
    tool_call: {
      response: allow?.tool_call?.response === true,
    },
  };
}

/**
 * Deterministic policy-path signature derived from evidence-referenced decisions.
 *
 * Signature is JCS-canonicalized to a string for stable equality.
 *
 * @param {{accepted: Map<string, any>}} store
 * @param {any[]} ordered
 * @returns {string}
 */
function policyPathSignature(store, ordered) {
  const getAccepted = (h) => store.accepted.get(h) || null;

  /** @type {any[]} */
  const steps = [];

  for (const entry of ordered) {
    if (entry.record_type !== 'model_call' && entry.record_type !== 'tool_call') continue;

    const policyHash = entry.envelope?.policy_decision_envelope_sha256;
    const policy = getAccepted(policyHash);
    if (!policy) continue;

    const env = policy.envelope;
    steps.push({
      policy: {
        policy_id: env?.policy?.policy_id,
        policy_version: env?.policy?.policy_version,
        policy_sha256: env?.policy?.policy_sha256,
      },
      request: {
        action: env?.request?.action,
        resource: env?.request?.resource,
      },
      decision: {
        result: env?.decision?.result,
        reason_codes: Object.keys(env?.decision?.reason_codes || {}).sort(),
        obligations: Object.keys(env?.decision?.obligations || {}).sort(),
      },
    });
  }

  return canonicalizeEnvelope({ policy_path: steps });
}

/**
 * Evidence equivalence across traces under an explicit variance policy.
 *
 * We compare multisets of evidence call summaries.
 * - model_call: request must match; response and usage may vary if allowed.
 * - tool_call: request must match; response may vary if allowed.
 *
 * @param {any} store
 * @param {any[]} baseOrdered
 * @param {any[]} candOrdered
 * @param {{model_call:{response:boolean,usage:boolean}, tool_call:{response:boolean}}} variance
 * @returns {{ok: true} | {ok:false, failure_kind: string}}
 */
function evidenceEquivalence(store, baseOrdered, candOrdered, variance) {
  const baseModel = summarizeModelCalls(baseOrdered, variance);
  const candModel = summarizeModelCalls(candOrdered, variance);

  if (!multisetEqual(baseModel.keys, candModel.keys)) {
    return { ok: false, failure_kind: 'model_call_mismatch' };
  }

  const baseTool = summarizeToolCalls(baseOrdered, variance);
  const candTool = summarizeToolCalls(candOrdered, variance);
  if (!multisetEqual(baseTool.keys, candTool.keys)) {
    return { ok: false, failure_kind: 'tool_call_mismatch' };
  }

  return { ok: true };
}

function summarizeModelCalls(ordered, variance) {
  const keys = [];
  for (const entry of ordered) {
    if (entry.record_type !== 'model_call') continue;
    const e = entry.envelope;
    const key = {
      model: e?.model,
      request: e?.request,
      outcome: { status: e?.outcome?.status },
    };
    if (!variance.model_call.response) key.response = e?.response;
    if (!variance.model_call.usage) key.usage = e?.usage;
    keys.push(canonicalizeEnvelope(key));
  }
  keys.sort();
  return { keys };
}

function summarizeToolCalls(ordered, variance) {
  const keys = [];
  for (const entry of ordered) {
    if (entry.record_type !== 'tool_call') continue;
    const e = entry.envelope;
    const key = {
      tool: e?.tool,
      request: e?.request,
      outcome: { status: e?.outcome?.status },
    };
    if (!variance.tool_call.response) key.response = e?.response;
    keys.push(canonicalizeEnvelope(key));
  }
  keys.sort();
  return { keys };
}

/**
 * @param {string[]} a
 * @param {string[]} b
 */
function multisetEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// --------------------------
// Variance reporting (hashes)
// --------------------------

import { createHash } from 'node:crypto';

function sha256HexUtf8(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function sortedList(xs) {
  return [...xs].filter((x) => typeof x === 'string').sort();
}

function buildVarianceReport(baseOrdered, candOrdered, variance) {
  const base = observeEvidenceHashes(baseOrdered);
  const cand = observeEvidenceHashes(candOrdered);

  return {
    allow_variance: variance,
    model_call: {
      request_sha256: {
        baseline: sortedList(base.model_call.request_sha256),
        candidate: sortedList(cand.model_call.request_sha256),
        equal: multisetEqual(sortedList(base.model_call.request_sha256), sortedList(cand.model_call.request_sha256)),
        allowed: false,
      },
      response_sha256: {
        baseline: sortedList(base.model_call.response_sha256),
        candidate: sortedList(cand.model_call.response_sha256),
        equal: multisetEqual(sortedList(base.model_call.response_sha256), sortedList(cand.model_call.response_sha256)),
        allowed: variance.model_call.response,
      },
    },
    tool_call: {
      request_sha256: {
        baseline: sortedList(base.tool_call.request_sha256),
        candidate: sortedList(cand.tool_call.request_sha256),
        equal: multisetEqual(sortedList(base.tool_call.request_sha256), sortedList(cand.tool_call.request_sha256)),
        allowed: false,
      },
      response_sha256: {
        baseline: sortedList(base.tool_call.response_sha256),
        candidate: sortedList(cand.tool_call.response_sha256),
        equal: multisetEqual(sortedList(base.tool_call.response_sha256), sortedList(cand.tool_call.response_sha256)),
        allowed: variance.tool_call.response,
      },
    },
  };
}

function observeEvidenceHashes(ordered) {
  const out = {
    model_call: { request_sha256: [], response_sha256: [] },
    tool_call: { request_sha256: [], response_sha256: [] },
  };
  for (const entry of ordered) {
    if (entry.record_type === 'model_call') {
      const e = entry.envelope;
      if (typeof e?.request?.sha256 === 'string') out.model_call.request_sha256.push(e.request.sha256);
      if (typeof e?.response?.sha256 === 'string') out.model_call.response_sha256.push(e.response.sha256);
    }
    if (entry.record_type === 'tool_call') {
      const e = entry.envelope;
      if (typeof e?.request?.sha256 === 'string') out.tool_call.request_sha256.push(e.request.sha256);
      if (typeof e?.response?.sha256 === 'string') out.tool_call.response_sha256.push(e.response.sha256);
    }
  }
  return out;
}
