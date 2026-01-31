import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CpoKernel } from '../src/cpo-kernel.js';
import { hashEnvelope } from '../src/flowversion-envelope.js';
import { resolveTraceChain } from '../src/replay/replay-index.js';
import { forensicReplay } from '../src/replay/forensic-replay.js';
import { invariantReplay } from '../src/replay/invariant-replay.js';
import { constrainedReplay } from '../src/replay/constrained-replay.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const INTEGRATION = JSON.parse(readFileSync(join(__dirname, '..', 'goldens', 'integration.e2e.goldens.json'), 'utf8'));

function deepClone(x) {
  return JSON.parse(JSON.stringify(x));
}

function vector(name) {
  const v = INTEGRATION.vectors.find((x) => x.name === name);
  assert.ok(v, `Missing vector: ${name}`);
  return v;
}

function stepByRecordType(v, recordType) {
  const s = (v.steps || []).find((x) => x.record_type === recordType);
  assert.ok(s, `Missing step ${recordType} in vector ${v.name}`);
  return s;
}

function commitStep(kernel, recordType, envelope, declaredHash) {
  const res = kernel.commit_action(recordType, declaredHash, deepClone(envelope));
  return res;
}

function commitE2EAllowToolCall(kernel) {
  const vModel = vector('e2e_allow_model_call_ok');
  const sAuth = stepByRecordType(vModel, 'auth_context');
  const authRes = commitStep(kernel, 'auth_context', sAuth.input, sAuth.sha256);
  assert.equal(authRes.ok, true);

  const vTool = vector('e2e_allow_tool_call_ok');
  const sPD = stepByRecordType(vTool, 'policy_decision');
  const pdRes = commitStep(kernel, 'policy_decision', sPD.input, sPD.sha256);
  assert.equal(pdRes.ok, true);

  const sTC = stepByRecordType(vTool, 'tool_call');
  const tcRes = commitStep(kernel, 'tool_call', sTC.input, sTC.sha256);
  assert.equal(tcRes.ok, true);

  return { trace_id: sAuth.input.trace.trace_id };
}

function commitE2EAllowModelCall(kernel) {
  const vModel = vector('e2e_allow_model_call_ok');
  const sAuth = stepByRecordType(vModel, 'auth_context');
  const authRes = commitStep(kernel, 'auth_context', sAuth.input, sAuth.sha256);
  assert.equal(authRes.ok, true);

  const sPD = stepByRecordType(vModel, 'policy_decision');
  const pdRes = commitStep(kernel, 'policy_decision', sPD.input, sPD.sha256);
  assert.equal(pdRes.ok, true);

  const sMC = stepByRecordType(vModel, 'model_call');
  const mcRes = commitStep(kernel, 'model_call', sMC.input, sMC.sha256);
  assert.equal(mcRes.ok, true);

  return { trace_id: sAuth.input.trace.trace_id, auth: sAuth.input, pd: sPD.input, mc: sMC.input };
}

function buildCandidateChainFromBaseline(baseline) {
  const trace_id = '11111111111111111111111111111111';
  const span_root = '1111111111111111';
  const span_pd = '2222222222222222';
  const span_mc = '3333333333333333';

  const auth = deepClone(baseline.auth);
  auth.trace.trace_id = trace_id;
  auth.trace.span_id = span_root;
  auth.trace.span_kind = 'root';
  delete auth.trace.parent_span_id;

  const auth_hash = hashEnvelope(auth);

  const pd = deepClone(baseline.pd);
  pd.trace.trace_id = trace_id;
  pd.trace.span_id = span_pd;
  pd.trace.span_kind = 'child';
  pd.trace.parent_span_id = span_root;
  pd.auth_context_envelope_sha256 = auth_hash;

  const pd_hash = hashEnvelope(pd);

  const mc = deepClone(baseline.mc);
  mc.trace.trace_id = trace_id;
  mc.trace.span_id = span_mc;
  mc.trace.span_kind = 'child';
  mc.trace.parent_span_id = span_pd;
  mc.auth_context_envelope_sha256 = auth_hash;
  mc.policy_decision_envelope_sha256 = pd_hash;

  // Allowed nondeterminism: response BlobRef changes.
  mc.response.sha256 = '3333333333333333333333333333333333333333333333333333333333333333';
  mc.response.size_bytes = 999;
  mc.response.content_type = 'application/json';

  const mc_hash = hashEnvelope(mc);
  return { trace_id, auth, auth_hash, pd, pd_hash, mc, mc_hash };
}

describe('PHASE5: Replay plumbing (evidence-locked)', () => {
  test('Forensic replay passes on an accepted Phase 4 certification trace and emits a content-addressed replay result artifact', () => {
    const kernel = new CpoKernel();
    const { trace_id } = commitE2EAllowToolCall(kernel);

    const clock = new Date('2026-01-31T00:00:00.000Z');
    const res = forensicReplay(kernel.store, trace_id, { clock });
    assert.equal(res.record.result, 'pass');
    assert.ok(res.artifact_sha256, 'Expected replay result artifact hash');

    // Stored as generic ledger artifact (not an envelope type).
    // @ts-ignore
    const stored = kernel.store.other_artifacts.get(res.artifact_sha256);
    assert.ok(stored);
    assert.equal(stored.artifact_type, 'replay_result');
  });

  test('Invariant replay passes on an accepted chain and emits a content-addressed replay result artifact', () => {
    const kernel = new CpoKernel();
    const { trace_id } = commitE2EAllowToolCall(kernel);

    const clock = new Date('2026-01-31T00:00:00.000Z');
    const res = invariantReplay(kernel.store, trace_id, { clock });
    assert.equal(res.record.result, 'pass');
    assert.ok(res.artifact_sha256);
  });

  test('Replay index resolves accepted + rejected-attempt artifacts when requested', () => {
    const kernel = new CpoKernel();
    const baseline = commitE2EAllowModelCall(kernel);

    // Submit a schema-valid model_call with incorrect declared hash -> rejected attempt persisted.
    const wrongDeclared = '0'.repeat(64);
    const mcHash = hashEnvelope(baseline.mc);
    assert.notEqual(wrongDeclared, mcHash);

    const rej = kernel.commit_action('model_call', wrongDeclared, deepClone(baseline.mc));
    assert.equal(rej.ok, false);
    assert.equal(rej.classification, 'HASH_MISMATCH');

    const chain = resolveTraceChain(kernel.store, baseline.trace_id, { include_rejected_attempts: true });
    assert.ok(chain);
    const rejected = chain.ordered.filter((x) => x.ledger_status === 'rejected_attempt');
    assert.ok(rejected.length >= 1, 'Expected at least one rejected-attempt artifact in resolved chain');
  });

  test('Constrained replay passes when ModelCallRecord.response BlobRef is allowed to vary', () => {
    const kernel = new CpoKernel();
    const baseline = commitE2EAllowModelCall(kernel);

    const candidate = buildCandidateChainFromBaseline(baseline);

    // Commit candidate chain with recomputed hashes.
    assert.equal(kernel.commit_action('auth_context', candidate.auth_hash, deepClone(candidate.auth)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', candidate.pd_hash, deepClone(candidate.pd)).ok, true);
    assert.equal(kernel.commit_action('model_call', candidate.mc_hash, deepClone(candidate.mc)).ok, true);

    const clock = new Date('2026-01-31T00:00:00.000Z');
    const res = constrainedReplay(kernel.store, {
      baseline_trace_id: baseline.trace_id,
      candidate_trace_id: candidate.trace_id,
      replay_policy: { allow_variance: { model_call: { allow_response_blobref: true } } },
      clock,
    });

    assert.equal(res.record.result, 'pass');
    assert.ok(Array.isArray(res.diagnostics.allowed_hash_differences));
    assert.ok(res.diagnostics.allowed_hash_differences.length >= 1, 'Expected at least one allowed hash difference');
  });

  test('Constrained replay fails when variance is not allowed', () => {
    const kernel = new CpoKernel();
    const baseline = commitE2EAllowModelCall(kernel);

    const candidate = buildCandidateChainFromBaseline(baseline);
    assert.equal(kernel.commit_action('auth_context', candidate.auth_hash, deepClone(candidate.auth)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', candidate.pd_hash, deepClone(candidate.pd)).ok, true);
    assert.equal(kernel.commit_action('model_call', candidate.mc_hash, deepClone(candidate.mc)).ok, true);

    const res = constrainedReplay(kernel.store, {
      baseline_trace_id: baseline.trace_id,
      candidate_trace_id: candidate.trace_id,
      replay_policy: { allow_variance: { model_call: { allow_response_blobref: false } } },
      clock: new Date('2026-01-31T00:00:00.000Z'),
      persist_result: false,
    });

    assert.equal(res.record.result, 'fail');
    assert.equal(res.record.failure_class, 'REPLAY_VARIANCE_VIOLATION');
  });
});
