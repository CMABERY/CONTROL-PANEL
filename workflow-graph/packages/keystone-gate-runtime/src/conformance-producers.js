/**
 * Phase 4 conformance harness: producer implementations.
 *
 * These are NOT production adapters.
 * They exist solely to exercise cross-producer determinism:
 * - different key insertion orders
 * - same semantic envelopes
 */

import { createHash } from 'node:crypto';
import { canonicalizeEnvelope, hashEnvelope } from './flowversion-envelope.js';

/**
 * Deterministic, wrong hash strategy used to prove HASH_MISMATCH.
 * This intentionally violates RFC 8785 canonicalization.
 */
export function hashEnvelopeWrong_Stringify(envelope) {
  const s = JSON.stringify(envelope); // preserves insertion order; NOT JCS
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

// --------------------
// AuthContext producers
// --------------------

/**
 * Producer A: builds objects in a "natural" property order.
 */
export function produceAuthContext_A() {
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'auth_context',
    ts_ms: 1769817600000,
    trace: {
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      span_id: '00f067aa0ba902b7',
      span_kind: 'root'
    },
    producer: {
      layer: 'cpo',
      component: 'ingress_gateway'
    },
    actor: {
      actor_kind: 'human',
      actor_id: 'user:12345'
    },
    credential: {
      credential_kind: 'jwt',
      issuer: 'auth.example',
      presented_hash_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      verified_at_ms: 1769817600000,
      expires_at_ms: 1769821200000
    },
    grants: {
      'role:viewer': true,
      'scope:read': true
    }
  };
}

/**
 * Producer B: same AuthContext, but permuted key insertion order.
 */
export function produceAuthContext_B() {
  const trace = { span_kind: 'root', span_id: '00f067aa0ba902b7', trace_id: '4bf92f3577b34da6a3ce929d0e0e4736' };
  const producer = { component: 'ingress_gateway', layer: 'cpo' };
  const actor = { actor_id: 'user:12345', actor_kind: 'human' };
  const credential = {
    verified_at_ms: 1769817600000,
    presented_hash_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    issuer: 'auth.example',
    expires_at_ms: 1769821200000,
    credential_kind: 'jwt'
  };
  const grants = { 'scope:read': true, 'role:viewer': true };

  return {
    ts_ms: 1769817600000,
    record_type: 'auth_context',
    canon_version: '1',
    spec_version: '1.0.0',
    producer,
    trace,
    credential,
    actor,
    grants
  };
}

// ----------------------------
// PolicyDecisionRecord producers
// ----------------------------

export function producePolicyDecisionAllow_Tool(auth_context_envelope_sha256) {
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'policy_decision',
    ts_ms: 1769817600250,
    trace: {
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      span_id: 'b7ad6b7169203331',
      span_kind: 'child',
      parent_span_id: '00f067aa0ba902b7'
    },
    producer: {
      layer: 'cpo',
      component: 'policy_engine'
    },
    auth_context_envelope_sha256,
    policy: {
      policy_id: 'cpo.default',
      policy_version: '2026_01_31',
      policy_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    },
    request: {
      action: 'tool.invoke',
      resource: 'tool:http.fetch'
    },
    decision: {
      result: 'allow',
      reason_codes: { allow: true },
      obligations: {}
    }
  };
}

export function producePolicyDecisionDeny_Tool(auth_context_envelope_sha256) {
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'policy_decision',
    ts_ms: 1769817600260,
    trace: {
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      span_id: 'b7ad6b7169203331',
      span_kind: 'child',
      parent_span_id: '00f067aa0ba902b7'
    },
    producer: {
      layer: 'cpo',
      component: 'policy_engine'
    },
    auth_context_envelope_sha256,
    policy: {
      policy_id: 'cpo.default',
      policy_version: '2026_01_31',
      policy_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    },
    request: {
      action: 'tool.invoke',
      resource: 'tool:http.fetch'
    },
    decision: {
      result: 'deny',
      reason_codes: { 'deny.policy': true },
      obligations: {}
    }
  };
}

export function producePolicyDecisionAllow_Model(auth_context_envelope_sha256) {
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'policy_decision',
    ts_ms: 1769817600200,
    trace: {
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      span_id: 'b7ad6b7169203332',
      span_kind: 'child',
      parent_span_id: '00f067aa0ba902b7'
    },
    producer: {
      layer: 'cpo',
      component: 'policy_engine'
    },
    auth_context_envelope_sha256,
    policy: {
      policy_id: 'cpo.default',
      policy_version: '2026_01_31',
      policy_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    },
    request: {
      action: 'model.call',
      resource: 'model:openai:gpt-4o-mini'
    },
    decision: {
      result: 'allow',
      reason_codes: { 'allow.policy': true },
      obligations: {}
    }
  };
}

// --------------------
// ModelCall producers
// --------------------

export function produceModelCall_A(auth_context_envelope_sha256, policy_decision_envelope_sha256) {
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'model_call',
    started_at_ms: 1769817600400,
    ended_at_ms: 1769817600500,
    trace: {
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      span_id: 'c3ab8ff13720e8ad',
      span_kind: 'child',
      parent_span_id: 'b7ad6b7169203332'
    },
    producer: { layer: 'flow', component: 'flow_runtime' },
    auth_context_envelope_sha256,
    policy_decision_envelope_sha256,
    model: { provider: 'openai', model: 'gpt-4o-mini' },
    request: {
      sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      size_bytes: 123,
      content_type: 'application/json'
    },
    response: {
      sha256: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      size_bytes: 456,
      content_type: 'application/json'
    },
    usage: { input_tokens: 10, output_tokens: 20, total_tokens: 30 },
    outcome: { status: 'ok' }
  };
}

export function produceModelCall_B(auth_context_envelope_sha256, policy_decision_envelope_sha256) {
  const base = produceModelCall_A(auth_context_envelope_sha256, policy_decision_envelope_sha256);
  return {
    record_type: base.record_type,
    canon_version: base.canon_version,
    spec_version: base.spec_version,
    started_at_ms: base.started_at_ms,
    ended_at_ms: base.ended_at_ms,
    producer: base.producer,
    trace: base.trace,
    policy_decision_envelope_sha256: base.policy_decision_envelope_sha256,
    auth_context_envelope_sha256: base.auth_context_envelope_sha256,
    model: base.model,
    request: base.request,
    response: base.response,
    usage: base.usage,
    outcome: base.outcome
  };
}

// --------------------
// ToolCall producers
// --------------------

/**
 * Tool adapter producer A: "normal" insertion order.
 */
export function produceToolCall_A(auth_hash, policy_hash) {
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'tool_call',
    started_at_ms: 1769817603000,
    ended_at_ms: 1769817603200,
    trace: {
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      span_id: '5c1d3a2b4f6e7d8c',
      span_kind: 'child',
      parent_span_id: 'b7ad6b7169203331'
    },
    producer: {
      layer: 'adapter',
      component: 'adapter_http'
    },
    auth_context_envelope_sha256: auth_hash,
    policy_decision_envelope_sha256: policy_hash,
    tool: {
      adapter_id: 'adapter.http',
      tool_name: 'http.fetch'
    },
    request: {
      content_type: 'application/json',
      sha256: '1111111111111111111111111111111111111111111111111111111111111111',
      size_bytes: 210
    },
    response: {
      content_type: 'application/json',
      sha256: '2222222222222222222222222222222222222222222222222222222222222222',
      size_bytes: 980
    },
    outcome: { status: 'ok' }
  };
}

/**
 * Tool adapter producer B: permuted insertion order.
 */
export function produceToolCall_B(auth_hash, policy_hash) {
  const tool = { tool_name: 'http.fetch', adapter_id: 'adapter.http' };
  const request = { size_bytes: 210, sha256: '1111111111111111111111111111111111111111111111111111111111111111', content_type: 'application/json' };
  const response = { sha256: '2222222222222222222222222222222222222222222222222222222222222222', content_type: 'application/json', size_bytes: 980 };
  const trace = {
    span_kind: 'child',
    parent_span_id: 'b7ad6b7169203331',
    trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
    span_id: '5c1d3a2b4f6e7d8c'
  };
  const producer = { component: 'adapter_http', layer: 'adapter' };

  return {
    outcome: { status: 'ok' },
    response,
    request,
    tool,
    policy_decision_envelope_sha256: policy_hash,
    auth_context_envelope_sha256: auth_hash,
    producer,
    trace,
    ended_at_ms: 1769817603200,
    started_at_ms: 1769817603000,
    record_type: 'tool_call',
    canon_version: '1',
    spec_version: '1.0.0'
  };
}

/**
 * Convenience: return canonical_json + sha256 for a (schema-valid) JSON object.
 */
export function computeCanonicalAndHash(envelope) {
  const canonical_json = canonicalizeEnvelope(envelope);
  const sha256 = hashEnvelope(envelope);
  return { canonical_json, sha256 };
}
