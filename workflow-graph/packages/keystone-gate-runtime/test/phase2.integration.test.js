import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateEnvelope, canonicalizeEnvelope, hashEnvelope } from '../src/flowversion-envelope.js';
import { CpoKernel } from '../src/cpo-kernel.js';
import { FailureClass, AcceptClass } from '../src/error-classification.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOLDENS = JSON.parse(readFileSync(join(__dirname, '..', 'goldens', 'integration.e2e.goldens.json'), 'utf8'));

function deepClone(x) {
  return JSON.parse(JSON.stringify(x));
}

/**
 * Pull a step from a vector by record_type (and optional predicate).
 */
function step(vectorName, recordType, predicate = undefined) {
  const v = GOLDENS.vectors.find((x) => x.name === vectorName);
  assert.ok(v, `Missing vector: ${vectorName}`);

  const candidates = v.steps.filter((x) => x.record_type === recordType);
  if (typeof predicate === 'function') {
    const s = candidates.find(predicate);
    assert.ok(s, `Missing step: ${vectorName}/${recordType} (predicate)`);
    return s;
  }

  assert.ok(candidates.length > 0, `Missing step: ${vectorName}/${recordType}`);
  if (candidates.length > 1) {
    throw new Error(`Ambiguous step lookup: ${vectorName}/${recordType} has ${candidates.length} matches`);
  }
  return candidates[0];
}

// -------------------------------
// Golden hashing + canonicalization
// -------------------------------

describe('IT-FV-HASH-001: FlowVersion canonicalization + hashing matches goldens', () => {
  test('e2e_allow_model_call_ok steps hash deterministically', () => {
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sPD = step('e2e_allow_model_call_ok', 'policy_decision');
    const sMC = step('e2e_allow_model_call_ok', 'model_call');

    for (const s of [sAuth, sPD, sMC]) {
      const v = validateEnvelope(s.input);
      assert.equal(v.ok, true, `${s.record_type} should validate`);

      const canon = canonicalizeEnvelope(s.input);
      assert.equal(canon, s.canonical_json, `${s.record_type} canonical_json mismatch`);

      const h = hashEnvelope(s.input);
      assert.equal(h, s.sha256, `${s.record_type} sha256 mismatch`);
    }
  });

  test('e2e_allow_tool_call_ok steps hash deterministically', () => {
    const sPD = step('e2e_allow_tool_call_ok', 'policy_decision');
    const sTC = step('e2e_allow_tool_call_ok', 'tool_call');

    for (const s of [sPD, sTC]) {
      const v = validateEnvelope(s.input);
      assert.equal(v.ok, true, `${s.record_type} should validate`);

      const canon = canonicalizeEnvelope(s.input);
      assert.equal(canon, s.canonical_json, `${s.record_type} canonical_json mismatch`);

      const h = hashEnvelope(s.input);
      assert.equal(h, s.sha256, `${s.record_type} sha256 mismatch`);
    }
  });
});

// ---------------------------------
// CPO commit_action boundary behavior
// ---------------------------------

describe('IT-CPO-ACCEPT-001: AuthContext accepted and persisted', () => {
  test('commit_action accepts auth_context when declared hash matches', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');

    const res = kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input));
    assert.equal(res.ok, true);
    assert.equal(res.classification, AcceptClass);
    assert.equal(res.envelope_hash, sAuth.sha256);

    const stored = kernel.store.getAccepted(sAuth.sha256);
    assert.ok(stored);
    assert.equal(stored.envelope_hash, sAuth.sha256);
  });
});

describe('IT-CPO-ACCEPT-002: PolicyDecision accepted only with existing AuthContext', () => {
  test('policy_decision rejected when auth prereq missing', () => {
    const kernel = new CpoKernel();
    const sPD = step('e2e_allow_model_call_ok', 'policy_decision');

    const res = kernel.commit_action('policy_decision', sPD.sha256, deepClone(sPD.input));
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.MISSING_PREREQ);
  });

  test('policy_decision accepted when auth prereq exists', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sPD = step('e2e_allow_model_call_ok', 'policy_decision');

    assert.equal(kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input)).ok, true);

    const res = kernel.commit_action('policy_decision', sPD.sha256, deepClone(sPD.input));
    assert.equal(res.ok, true);
    assert.equal(res.envelope_hash, sPD.sha256);
  });
});

describe('IT-CPO-ACCEPT-003: ModelCall accepted only with allow policy and trace continuity', () => {
  test('model_call accepted end-to-end (auth -> pd allow -> model_call ok)', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sPD = step('e2e_allow_model_call_ok', 'policy_decision');
    const sMC = step('e2e_allow_model_call_ok', 'model_call');

    assert.equal(kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', sPD.sha256, deepClone(sPD.input)).ok, true);

    const res = kernel.commit_action('model_call', sMC.sha256, deepClone(sMC.input));
    assert.equal(res.ok, true);
    assert.equal(res.envelope_hash, sMC.sha256);
  });

  test('model_call rejected when declared hash mismatches computed hash', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sPD = step('e2e_allow_model_call_ok', 'policy_decision');
    const sMC = step('e2e_allow_model_call_ok', 'model_call');

    assert.equal(kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', sPD.sha256, deepClone(sPD.input)).ok, true);

    const res = kernel.commit_action('model_call', '0'.repeat(64), deepClone(sMC.input));
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.HASH_MISMATCH);

    // hash mismatch is a ledger artifact (rejected attempt)
    const computed = hashEnvelope(sMC.input);
    const rej = kernel.store.rejected_attempts.get(computed);
    assert.ok(rej);
    assert.equal(rej.classification, FailureClass.HASH_MISMATCH);
  });

  test('model_call rejected when trace_id differs from prereqs', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sPD = step('e2e_allow_model_call_ok', 'policy_decision');
    const sMC = step('e2e_allow_model_call_ok', 'model_call');

    assert.equal(kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', sPD.sha256, deepClone(sPD.input)).ok, true);

    const bad = deepClone(sMC.input);
    bad.trace.trace_id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    const badHash = hashEnvelope(bad);
    const res = kernel.commit_action('model_call', badHash, bad);
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.TRACE_VIOLATION);
  });

  test('model_call rejected when policy_decision prereq missing', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sMC = step('e2e_allow_model_call_ok', 'model_call');

    assert.equal(kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input)).ok, true);

    const res = kernel.commit_action('model_call', sMC.sha256, deepClone(sMC.input));
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.MISSING_PREREQ);
  });
});

describe('IT-ADAPTER-ACCEPT-001: ToolCall accepted only with allow policy and trace continuity', () => {
  test('tool_call accepted end-to-end (auth -> pd allow -> tool_call ok)', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const sPDTool = step('e2e_allow_tool_call_ok', 'policy_decision');
    const sTC = step('e2e_allow_tool_call_ok', 'tool_call');

    assert.equal(kernel.commit_action('auth_context', sAuth.sha256, deepClone(sAuth.input)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', sPDTool.sha256, deepClone(sPDTool.input)).ok, true);

    const res = kernel.commit_action('tool_call', sTC.sha256, deepClone(sTC.input));
    assert.equal(res.ok, true);
    assert.equal(res.envelope_hash, sTC.sha256);
  });

  test('tool_call rejected when policy decision is deny', () => {
    const kernel = new CpoKernel();

    // AuthContext (service actor) fixture.
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
    const authSvcHash = hashEnvelope(authSvc);
    assert.equal(kernel.commit_action('auth_context', authSvcHash, deepClone(authSvc)).ok, true);

    const pdDeny = {
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
    const pdDenyHash = hashEnvelope(pdDeny);
    assert.equal(kernel.commit_action('policy_decision', pdDenyHash, deepClone(pdDeny)).ok, true);

    const tcAttempt = {
      spec_version: '1.0.0',
      canon_version: '1',
      record_type: 'tool_call',
      started_at_ms: 1769817601000,
      ended_at_ms: 1769817601100,
      trace: { trace_id: authSvc.trace.trace_id, span_id: '0000000000000004', parent_span_id: pdDeny.trace.span_id, span_kind: 'child' },
      producer: { layer: 'adapter', component: 'adapter_http' },
      auth_context_envelope_sha256: authSvcHash,
      policy_decision_envelope_sha256: pdDenyHash,
      tool: { adapter_id: 'adapter.http', tool_name: 'http.fetch' },
      request: { content_type: 'application/json', sha256: '1111111111111111111111111111111111111111111111111111111111111111', size_bytes: 34 },
      response: { content_type: 'application/json', sha256: '2222222222222222222222222222222222222222222222222222222222222222', size_bytes: 89 },
      outcome: { status: 'ok' }
    };

    const tcAttemptHash = hashEnvelope(tcAttempt);
    const res = kernel.commit_action('tool_call', tcAttemptHash, deepClone(tcAttempt));
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.UNAUTHORIZED_EXECUTION);

    // unauthorized execution is a ledger artifact (rejected attempt)
    const rej = kernel.store.rejected_attempts.get(tcAttemptHash);
    assert.ok(rej);
    assert.equal(rej.classification, FailureClass.UNAUTHORIZED_EXECUTION);
  });
});

// ---------------------------------
// Schema rejection is fail-closed
// ---------------------------------

describe('IT-SCHEMA-REJECT-001: Schema rejects are terminal and non-persistent', () => {
  test('missing trace_id -> SCHEMA_REJECT and not stored', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const bad = deepClone(sAuth.input);
    delete bad.trace.trace_id;

    const res = kernel.commit_action('auth_context', '0'.repeat(64), bad);
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.SCHEMA_REJECT);

    // No canonical bytes stored, so no rejected-attempt record.
    assert.equal(kernel.store.rejected_attempts.size, 0);
    assert.equal(kernel.store.accepted.size, 0);
  });

  test('extra unknown field -> SCHEMA_REJECT', () => {
    const kernel = new CpoKernel();
    const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
    const bad = deepClone(sAuth.input);
    bad.extra = 1;

    const res = kernel.commit_action('auth_context', '0'.repeat(64), bad);
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.SCHEMA_REJECT);
  });
});

// ---------------------------------
// Closed-world record_type
// ---------------------------------

describe('IT-RECORD-TYPE-001: Unknown record types are forbidden', () => {
  test('unknown record_type -> RECORD_TYPE_FORBIDDEN', () => {
    const kernel = new CpoKernel();
    const res = kernel.commit_action('not_a_real_record', '0'.repeat(64), {});
    assert.equal(res.ok, false);
    assert.equal(res.classification, FailureClass.RECORD_TYPE_FORBIDDEN);
  });
});
