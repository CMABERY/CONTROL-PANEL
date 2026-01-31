import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeEnvelope, hashEnvelope, validateEnvelope } from '../src/flowversion-envelope.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

const integration = JSON.parse(readFileSync(join(root, 'goldens', 'integration.e2e.goldens.json'), 'utf8'));

function step(vectorName, recordType) {
  const v = integration.vectors.find((x) => x.name === vectorName);
  if (!v) throw new Error(`Missing vector: ${vectorName}`);
  const s = v.steps.find((x) => x.record_type === recordType && x.input);
  if (!s) throw new Error(`Missing input step: ${vectorName}/${recordType}`);
  return s;
}

function deepClone(x) {
  return JSON.parse(JSON.stringify(x));
}

/**
 * Create a new object with the same content but reversed insertion order of keys.
 * Arrays preserved.
 */
function reorderDeep(v) {
  if (v === null) return null;
  if (Array.isArray(v)) return v.map(reorderDeep);
  if (typeof v !== 'object') return v;

  const obj = /** @type {Record<string, any>} */ (v);
  const keys = Object.keys(obj);
  keys.reverse();
  const out = {};
  for (const k of keys) {
    out[k] = reorderDeep(obj[k]);
  }
  return out;
}

function assertValid(envelope) {
  const r = validateEnvelope(envelope);
  if (!r.ok) {
    throw new Error(`Fixture did not validate: ${JSON.stringify(r.errors, null, 2)}`);
  }
}

// Base fixtures from integration goldens.
const authHuman = deepClone(step('e2e_allow_model_call_ok', 'auth_context').input);
const pdAllowModel = deepClone(step('e2e_allow_model_call_ok', 'policy_decision').input);
const modelCall = deepClone(step('e2e_allow_model_call_ok', 'model_call').input);
const pdAllowTool = deepClone(step('e2e_allow_tool_call_ok', 'policy_decision').input);
const toolCall = deepClone(step('e2e_allow_tool_call_ok', 'tool_call').input);

// Additional fixtures (deny path) aligned with Phase 2 tests.
const authSvc = {
  spec_version: '1.0.0',
  canon_version: '1',
  record_type: 'auth_context',
  ts_ms: 1769817600000,
  trace: { trace_id: '4bf92f3577b34da6a3ce929d0e0e4736', span_id: '0000000000000002', span_kind: 'root' },
  producer: { layer: 'cpo', component: 'ingress_gateway' },
  actor: { actor_id: 'svc:adapter.http', actor_kind: 'service' },
  credential: {
    credential_kind: 'mtls',
    issuer: 'mtls.example',
    presented_hash_sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    verified_at_ms: 1769817600000,
    expires_at_ms: 1769821200000
  },
  grants: { 'role:adapter': true }
};

// hashes used in deny fixtures.
const authSvcHash = hashEnvelope(authSvc);

const pdDenyTool = {
  spec_version: '1.0.0',
  canon_version: '1',
  record_type: 'policy_decision',
  ts_ms: 1769817600100,
  trace: { trace_id: authSvc.trace.trace_id, span_id: '0000000000000003', parent_span_id: authSvc.trace.span_id, span_kind: 'child' },
  producer: { layer: 'cpo', component: 'policy_engine' },
  auth_context_envelope_sha256: authSvcHash,
  policy: { policy_id: 'cpo.default', policy_version: '2026_01_31', policy_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' },
  request: { action: 'tool.invoke', resource: 'tool:http.fetch' },
  decision: { result: 'deny', reason_codes: { 'deny.policy': true }, obligations: {} }
};
const pdDenyHash = hashEnvelope(pdDenyTool);

const tcUnauthorized = {
  spec_version: '1.0.0',
  canon_version: '1',
  record_type: 'tool_call',
  started_at_ms: 1769817605000,
  ended_at_ms: 1769817605200,
  trace: { trace_id: authSvc.trace.trace_id, span_id: '0000000000000004', parent_span_id: pdDenyTool.trace.span_id, span_kind: 'child' },
  producer: { layer: 'adapter', component: 'adapter_fs' },
  auth_context_envelope_sha256: authSvcHash,
  policy_decision_envelope_sha256: pdDenyHash,
  tool: { adapter_id: 'adapter.filesystem', tool_name: 'filesystem.delete' },
  request: { content_type: 'application/json', sha256: '5555555555555555555555555555555555555555555555555555555555555555', size_bytes: 111 },
  response: { content_type: 'application/json', sha256: '6666666666666666666666666666666666666666666666666666666666666666', size_bytes: 222 },
  outcome: { status: 'ok' }
};

// Sanity: fixtures validate.
for (const f of [authHuman, pdAllowModel, modelCall, pdAllowTool, toolCall, authSvc, pdDenyTool, tcUnauthorized]) {
  assertValid(f);
}

function makeVector({ name, record_type, prereqs = [], inputs, expected }) {
  return { name, record_type, prereqs, inputs, expected };
}

// Canonical expectations from FlowVersion implementation.
function expectedFor(envelope) {
  return { canonical_json: canonicalizeEnvelope(envelope), sha256: hashEnvelope(envelope) };
}

const vectors = [];

// Positive multi-producer equivalence vectors.
vectors.push(
  makeVector({
    name: 'conf_auth_context_same_envelope_different_key_order',
    record_type: 'auth_context',
    inputs: [
      { producer_id: 'cpo_ingress_ref', input_json: JSON.stringify(authHuman) },
      { producer_id: 'cpo_ingress_alt', input_json: JSON.stringify(reorderDeep(authHuman)) }
    ],
    expected: { ...expectedFor(authHuman), commit: { overall: 'accept' } }
  })
);

vectors.push(
  makeVector({
    name: 'conf_policy_decision_same_envelope_different_key_order',
    record_type: 'policy_decision',
    prereqs: [
      { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 }
    ],
    inputs: [
      { producer_id: 'cpo_policy_ref', input_json: JSON.stringify(pdAllowModel) },
      { producer_id: 'cpo_policy_alt', input_json: JSON.stringify(reorderDeep(pdAllowModel)) }
    ],
    expected: { ...expectedFor(pdAllowModel), commit: { overall: 'accept' } }
  })
);

// Additional positive vector: allow tool.invoke policy decision (used as prereq for ToolCall).
vectors.push(
  makeVector({
    name: 'conf_policy_decision_allow_tool_invoke_same_envelope_different_key_order',
    record_type: 'policy_decision',
    prereqs: [
      { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 }
    ],
    inputs: [
      { producer_id: 'cpo_policy_tool_ref', input_json: JSON.stringify(pdAllowTool) },
      { producer_id: 'cpo_policy_tool_alt', input_json: JSON.stringify(reorderDeep(pdAllowTool)) }
    ],
    expected: { ...expectedFor(pdAllowTool), commit: { overall: 'accept' } }
  })
);

// Additional positive vector: service AuthContext (used as prereq for deny-path tests).
vectors.push(
  makeVector({
    name: 'conf_auth_context_service_same_envelope_different_key_order',
    record_type: 'auth_context',
    inputs: [
      { producer_id: 'cpo_ingress_svc_ref', input_json: JSON.stringify(authSvc) },
      { producer_id: 'cpo_ingress_svc_alt', input_json: JSON.stringify(reorderDeep(authSvc)) }
    ],
    expected: { ...expectedFor(authSvc), commit: { overall: 'accept' } }
  })
);

// Additional positive vector: deny policy decision (used as prereq for UNAUTHORIZED_EXECUTION vector).
vectors.push(
  makeVector({
    name: 'conf_policy_decision_deny_tool_invoke_same_envelope_different_key_order',
    record_type: 'policy_decision',
    prereqs: [
      { record_type: 'auth_context', envelope_sha256: authSvcHash }
    ],
    inputs: [
      { producer_id: 'cpo_policy_deny_ref', input_json: JSON.stringify(pdDenyTool) },
      { producer_id: 'cpo_policy_deny_alt', input_json: JSON.stringify(reorderDeep(pdDenyTool)) }
    ],
    expected: { ...expectedFor(pdDenyTool), commit: { overall: 'accept' } }
  })
);

vectors.push(
  makeVector({
    name: 'conf_model_call_same_envelope_different_key_order',
    record_type: 'model_call',
    prereqs: [
      { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 },
      { record_type: 'policy_decision', envelope_sha256: expectedFor(pdAllowModel).sha256 }
    ],
    inputs: [
      { producer_id: 'flow_runtime_ref', input_json: JSON.stringify(modelCall) },
      { producer_id: 'flow_runtime_alt', input_json: JSON.stringify(reorderDeep(modelCall)) }
    ],
    expected: { ...expectedFor(modelCall), commit: { overall: 'accept' } }
  })
);

vectors.push(
  makeVector({
    name: 'conf_tool_call_same_envelope_different_key_order',
    record_type: 'tool_call',
    prereqs: [
      { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 },
      { record_type: 'policy_decision', envelope_sha256: expectedFor(pdAllowTool).sha256 }
    ],
    inputs: [
      { producer_id: 'adapter_http_ref', input_json: JSON.stringify(toolCall) },
      { producer_id: 'adapter_http_alt', input_json: JSON.stringify(reorderDeep(toolCall)) }
    ],
    expected: { ...expectedFor(toolCall), commit: { overall: 'accept' } }
  })
);

// Negative: schema reject is identical across producers.
{
  const bad1 = deepClone(authHuman);
  bad1.extra = 1;
  const bad2 = reorderDeep(bad1);

  vectors.push(
    makeVector({
      name: 'conf_schema_reject_additional_properties',
      record_type: 'auth_context',
      inputs: [
        { producer_id: 'cpo_ingress_ref', input_json: JSON.stringify(bad1) },
        { producer_id: 'cpo_ingress_alt', input_json: JSON.stringify(bad2) }
      ],
      expected: { canonical_json: null, sha256: null, commit: { overall: 'reject', classification: 'SCHEMA_REJECT' } }
    })
  );
}

// Negative: hash mismatch (buggy producer hashing) yields HASH_MISMATCH deterministically.
{
  vectors.push(
    makeVector({
      name: 'conf_hash_mismatch_buggy_producers',
      record_type: 'tool_call',
      prereqs: [
        { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 },
        { record_type: 'policy_decision', envelope_sha256: expectedFor(pdAllowTool).sha256 }
      ],
      inputs: [
        { producer_id: 'adapter_http_buggy_stringify', input_json: JSON.stringify(toolCall) },
        { producer_id: 'adapter_http_buggy_stringify_alt', input_json: JSON.stringify(reorderDeep(toolCall)) }
      ],
      expected: { ...expectedFor(toolCall), commit: { overall: 'reject', classification: 'HASH_MISMATCH' } }
    })
  );
}

// Negative: missing prereq.
{
  const tcMissing = deepClone(toolCall);
  tcMissing.policy_decision_envelope_sha256 = '1'.repeat(64);
  assertValid(tcMissing);

  vectors.push(
    makeVector({
      name: 'conf_missing_prereq_policy_decision',
      record_type: 'tool_call',
      prereqs: [
        { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 }
      ],
      inputs: [
        { producer_id: 'adapter_http_ref', input_json: JSON.stringify(tcMissing) },
        { producer_id: 'adapter_http_alt', input_json: JSON.stringify(reorderDeep(tcMissing)) }
      ],
      expected: { ...expectedFor(tcMissing), commit: { overall: 'reject', classification: 'MISSING_PREREQ' } }
    })
  );
}

// Negative: trace violation.
{
  const tcTrace = deepClone(toolCall);
  tcTrace.trace.trace_id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  assertValid(tcTrace);

  vectors.push(
    makeVector({
      name: 'conf_trace_violation_trace_id_mismatch',
      record_type: 'tool_call',
      prereqs: [
        { record_type: 'auth_context', envelope_sha256: expectedFor(authHuman).sha256 },
        { record_type: 'policy_decision', envelope_sha256: expectedFor(pdAllowTool).sha256 }
      ],
      inputs: [
        { producer_id: 'adapter_http_ref', input_json: JSON.stringify(tcTrace) },
        { producer_id: 'adapter_http_alt', input_json: JSON.stringify(reorderDeep(tcTrace)) }
      ],
      expected: { ...expectedFor(tcTrace), commit: { overall: 'reject', classification: 'TRACE_VIOLATION' } }
    })
  );
}

// Negative: unauthorized execution (deny policy).
{
  vectors.push(
    makeVector({
      name: 'conf_unauthorized_execution_policy_deny',
      record_type: 'tool_call',
      prereqs: [
        { record_type: 'auth_context', envelope_sha256: authSvcHash },
        { record_type: 'policy_decision', envelope_sha256: pdDenyHash }
      ],
      inputs: [
        { producer_id: 'adapter_fs_ref', input_json: JSON.stringify(tcUnauthorized) },
        { producer_id: 'adapter_fs_alt', input_json: JSON.stringify(reorderDeep(tcUnauthorized)) }
      ],
      expected: { ...expectedFor(tcUnauthorized), commit: { overall: 'reject', classification: 'UNAUTHORIZED_EXECUTION' } }
    })
  );
}

const out = {
  _meta: {
    spec_version: '1.0.0',
    canon_version: '1',
    generated_at: '2026-01-31T00:00:00Z',
    generator: 'phase4 conformance spec (multi-producer)'
  },
  vectors
};

writeFileSync(join(root, 'goldens', 'conformance.multi_producer.goldens.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');
console.log(`Wrote goldens/conformance.multi_producer.goldens.json with ${vectors.length} vectors`);
