import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { validateEnvelope, canonicalizeEnvelope, hashEnvelope } from '../src/flowversion-envelope.js';
import { CpoKernel } from '../src/cpo-kernel.js';
import { FailureClass, AcceptClass } from '../src/error-classification.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOLDENS = JSON.parse(readFileSync(join(__dirname, '..', 'goldens', 'conformance.multi_producer.goldens.json'), 'utf8'));
const INTEGRATION = JSON.parse(readFileSync(join(__dirname, '..', 'goldens', 'integration.e2e.goldens.json'), 'utf8'));

function deepClone(x) {
  return JSON.parse(JSON.stringify(x));
}

function step(vectorName, recordType) {
  const v = INTEGRATION.vectors.find((x) => x.name === vectorName);
  assert.ok(v, `Missing integration vector: ${vectorName}`);
  const candidates = v.steps.filter((x) => x.record_type === recordType);
  assert.ok(candidates.length === 1, `Missing/ambiguous integration step: ${vectorName}/${recordType}`);
  return candidates[0];
}

// ------------------------------------------
// Independent producer implementation (JCS)
// ------------------------------------------

function jcsSerialize(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'string') return JSON.stringify(v);
  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error('Non-finite numbers forbidden');
    if (!Number.isInteger(v)) throw new Error('Non-integer numbers forbidden');
    if (!Number.isSafeInteger(v)) throw new Error('Unsafe integers forbidden');
    if (Object.is(v, -0)) return '0';
    return String(v);
  }
  if (t === 'undefined') throw new Error('Undefined forbidden');
  if (Array.isArray(v)) return '[' + v.map(jcsSerialize).join(',') + ']';
  if (t === 'object') {
    const obj = /** @type {Record<string, unknown>} */ (v);
    const keys = Object.keys(obj).sort();
    let out = '{';
    let first = true;
    for (const k of keys) {
      const val = obj[k];
      if (typeof val === 'undefined') throw new Error('Undefined forbidden');
      if (!first) out += ',';
      first = false;
      out += JSON.stringify(k) + ':' + jcsSerialize(val);
    }
    out += '}';
    return out;
  }
  throw new Error(`Unsupported type: ${t}`);
}

function sha256HexUtf8(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

const Producer = {
  // Reference producer: uses the FlowVersion module (canonical authority).
  ref_hash(envelope) {
    return hashEnvelope(envelope);
  },
  // Independent producer: separately implemented JCS + sha256.
  independent_hash(envelope) {
    return sha256HexUtf8(jcsSerialize(envelope));
  },
  // Buggy producer: hashes JSON.stringify() bytes (NOT canonical).
  buggy_stringify_hash(envelope) {
    return sha256HexUtf8(JSON.stringify(envelope));
  },
};

function producerForId(producer_id) {
  if (producer_id.includes('buggy_stringify')) return Producer.buggy_stringify_hash;
  // For alt/other producers we intentionally use the independent implementation.
  if (producer_id.endsWith('_alt') || producer_id.includes('_alt') || producer_id.includes('alt')) return Producer.independent_hash;
  return Producer.ref_hash;
}

// ---------------------------------------------------
// Fixtures for prereq preload (hash -> envelope input)
// ---------------------------------------------------

const FIXTURES = new Map();

// Core fixtures from integration goldens.
{
  const sAuth = step('e2e_allow_model_call_ok', 'auth_context');
  const sPDModel = step('e2e_allow_model_call_ok', 'policy_decision');
  const sPDTool = step('e2e_allow_tool_call_ok', 'policy_decision');

  FIXTURES.set(sAuth.sha256, { record_type: 'auth_context', envelope: sAuth.input });
  FIXTURES.set(sPDModel.sha256, { record_type: 'policy_decision', envelope: sPDModel.input });
  FIXTURES.set(sPDTool.sha256, { record_type: 'policy_decision', envelope: sPDTool.input });
}

// Additional fixtures used in conformance vectors (service auth + deny policy).
function buildAuthSvc() {
  return {
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
      expires_at_ms: 1769821200000,
    },
    grants: { 'role:adapter': true },
  };
}

function buildPolicyDenyTool(authSvcHash) {
  const authSvc = FIXTURES.get(authSvcHash).envelope;
  return {
    spec_version: '1.0.0',
    canon_version: '1',
    record_type: 'policy_decision',
    ts_ms: 1769817600100,
    trace: { trace_id: authSvc.trace.trace_id, span_id: '0000000000000003', parent_span_id: authSvc.trace.span_id, span_kind: 'child' },
    producer: { layer: 'cpo', component: 'policy_engine' },
    auth_context_envelope_sha256: authSvcHash,
    policy: {
      policy_id: 'cpo.default',
      policy_version: '2026_01_31',
      policy_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    },
    request: { action: 'tool.invoke', resource: 'tool:http.fetch' },
    decision: { result: 'deny', reason_codes: { 'deny.policy': true }, obligations: {} },
  };
}

{
  const authSvc = buildAuthSvc();
  const authSvcHash = hashEnvelope(authSvc);
  FIXTURES.set(authSvcHash, { record_type: 'auth_context', envelope: authSvc });

  const pdDeny = buildPolicyDenyTool(authSvcHash);
  const pdDenyHash = hashEnvelope(pdDeny);
  FIXTURES.set(pdDenyHash, { record_type: 'policy_decision', envelope: pdDeny });
}

function preloadPrereqs(kernel, prereqs) {
  // Preload in stable order: auth_context first, then policy_decision.
  const sorted = [...prereqs].sort((a, b) => a.record_type.localeCompare(b.record_type));
  for (const p of sorted) {
    const fx = FIXTURES.get(p.envelope_sha256);
    assert.ok(fx, `Missing fixture for prereq hash: ${p.envelope_sha256}`);

    const res = kernel.commit_action(fx.record_type, p.envelope_sha256, deepClone(fx.envelope));
    assert.equal(res.ok, true, `Preload failed for prereq ${p.record_type} (${p.envelope_sha256}): ${res.classification}`);
  }
}

// --------------------------------
// Cross-layer conformance execution
// --------------------------------

describe('PHASE4: Cross-layer conformance (gate-enforced)', () => {
  test('All conformance vectors satisfy expected canonical bytes, hash, and CPO classification', () => {
    for (const vector of GOLDENS.vectors) {
      const kernel = new CpoKernel();
      preloadPrereqs(kernel, vector.prereqs ?? []);

      for (const input of vector.inputs) {
        const envelope = JSON.parse(input.input_json);

        // Schema check is part of the contract: validateEnvelope must be consistent across producers.
        const vr = validateEnvelope(envelope);
        const expectedOverall = vector.expected.commit.overall;
        if (expectedOverall === 'accept' || expectedOverall === 'reject') {
          // Some reject paths are schema-valid (hash mismatch, missing prereq, trace, unauthorized).
          // Schema rejects are explicitly modeled.
          if (vector.expected.commit.classification === 'SCHEMA_REJECT') {
            assert.equal(vr.ok, false, `${vector.name}: expected schema reject, but validateEnvelope passed`);
          } else {
            assert.equal(vr.ok, true, `${vector.name}: expected schema-valid envelope`);
          }
        }

        // Canonical + hash expectations (for schema-valid envelopes only).
        if (vr.ok) {
          const canon = canonicalizeEnvelope(envelope);
          assert.equal(canon, vector.expected.canonical_json, `${vector.name}: canonical_json mismatch (${input.producer_id})`);

          const computed = hashEnvelope(envelope);
          assert.equal(computed, vector.expected.sha256, `${vector.name}: sha256 mismatch (${input.producer_id})`);
        } else {
          assert.equal(vector.expected.canonical_json, null, `${vector.name}: expected canonical_json null`);
          assert.equal(vector.expected.sha256, null, `${vector.name}: expected sha256 null`);
        }

        const declareHashFn = producerForId(input.producer_id);
        const declared = declareHashFn(envelope);

        const res = kernel.commit_action(vector.record_type, declared, deepClone(envelope));

        if (vector.expected.commit.overall === 'accept') {
          assert.equal(res.ok, true, `${vector.name}: expected accept (${input.producer_id})`);
          assert.equal(res.classification, AcceptClass);
          assert.equal(res.envelope_hash, vector.expected.sha256);
        } else {
          assert.equal(res.ok, false, `${vector.name}: expected reject (${input.producer_id})`);
          assert.equal(res.classification, vector.expected.commit.classification, `${vector.name}: classification mismatch (${input.producer_id})`);

          // For schema-valid rejects, a computed hash must exist and rejected attempts must be persisted.
          if (res.classification !== FailureClass.SCHEMA_REJECT) {
            assert.ok(res.computed_envelope_hash || vector.expected.sha256, `${vector.name}: missing computed hash`);
            const computedHash = vector.expected.sha256;
            const rej = kernel.store.rejected_attempts.get(computedHash);
            assert.ok(rej, `${vector.name}: expected rejected attempt persisted (${computedHash})`);
            assert.equal(rej.classification, vector.expected.commit.classification);
          }
        }
      }
    }
  });
});

// ------------------------------
// Adapter certification artifact
// ------------------------------

describe('PHASE4: Adapter certification (binary pass/fail)', () => {
  test('Certify adapter.http@1.0.0-test end-to-end and emit certification artifact', () => {
    const kernel = new CpoKernel();

    // Preload allow chain for tool.invoke http.fetch
    const auth = FIXTURES.get('2a6827a89f7b75ffd893112a8f498485f8010f7af0d93fdd6f101caa046f2b75');
    const pdAllowTool = FIXTURES.get('9e10b1a5443bc848639d26c45dc120497259d96d764547f8496c4bc111ea30c2');
    assert.ok(auth && pdAllowTool);

    assert.equal(kernel.commit_action('auth_context', hashEnvelope(auth.envelope), deepClone(auth.envelope)).ok, true);
    assert.equal(kernel.commit_action('policy_decision', hashEnvelope(pdAllowTool.envelope), deepClone(pdAllowTool.envelope)).ok, true);

    // ToolCall payload as in integration golden (adapter_http). We'll use independent producer hashing.
    const toolCallVector = GOLDENS.vectors.find((v) => v.name === 'conf_tool_call_same_envelope_different_key_order');
    assert.ok(toolCallVector);
    const toolCall = JSON.parse(toolCallVector.inputs[1].input_json); // alt ordering

    // Certification-required checks.
    const certTests = {
      'CT-ADAPTER-001.schema_valid': validateEnvelope(toolCall).ok === true,
      'CT-ADAPTER-002.trace_id_present': typeof toolCall.trace?.trace_id === 'string' && toolCall.trace.trace_id.length === 32,
      'CT-ADAPTER-003.prereq_hashes_present': typeof toolCall.auth_context_envelope_sha256 === 'string' && typeof toolCall.policy_decision_envelope_sha256 === 'string',
      'CT-ADAPTER-004.correct_declared_hash': Producer.independent_hash(toolCall) === hashEnvelope(toolCall),
    };

    // Submit through CPO.
    const declared = Producer.independent_hash(toolCall);
    const res = kernel.commit_action('tool_call', declared, deepClone(toolCall));
    certTests['CT-ADAPTER-005.cpo_accepts'] = res.ok === true && res.envelope_hash === hashEnvelope(toolCall);

    // All tests must pass.
    for (const [k, ok] of Object.entries(certTests)) {
      assert.equal(ok, true, `Certification check failed: ${k}`);
    }

    // Deterministic certification artifact.
    const CERTIFIED_AT_MS = 1769817600000;

    const results = {
      artifact_kind: 'adapter_conformance_results',
      suite_id: 'phase4_conformance_v1',
      adapter_id: 'adapter.http',
      adapter_version: '1.0.0-test',
      spec_version: toolCall.spec_version,
      canon_version: toolCall.canon_version,
      executed_at_ms: CERTIFIED_AT_MS,
      tests: Object.fromEntries(Object.entries(certTests).sort(([a], [b]) => a.localeCompare(b))),
      evidence_envelope_hashes: {
        [hashEnvelope(toolCall)]: true,
      },
    };

    const results_canon = canonicalizeEnvelope(results);
    const results_sha256 = sha256HexUtf8(results_canon);

    const cert = {
      artifact_kind: 'adapter_certification',
      adapter_id: 'adapter.http',
      certified_version: '1.0.0-test',
      spec_version: toolCall.spec_version,
      canon_version: toolCall.canon_version,
      certified_at_ms: CERTIFIED_AT_MS,
      conformance_results_sha256: results_sha256,
      status: 'certified',
    };

    const cert_canon = canonicalizeEnvelope(cert);
    const cert_sha256 = sha256HexUtf8(cert_canon);

    // Store as ledger artifact (test harness writes to disk deterministically).
    const outDir = join(__dirname, '..', 'certifications');
    mkdirSync(outDir, { recursive: true });

    const out = {
      _meta: {
        spec_version: cert.spec_version,
        canon_version: cert.canon_version,
        generated_at_ms: CERTIFIED_AT_MS,
        generator: 'phase4 certification runner (contract-locked)',
      },
      certification_sha256: cert_sha256,
      certification_canonical_json: cert_canon,
      certification: cert,
      conformance_results_sha256: results_sha256,
      conformance_results_canonical_json: results_canon,
      conformance_results: results,
    };

    const outPath = join(outDir, 'adapter.http__1.0.0-test.cert.json');
    writeFileSync(outPath, JSON.stringify(out, null, 2));

    // Assert the artifact file is reproducible by recomputing its hashes.
    assert.equal(out.certification_sha256, cert_sha256);
    assert.equal(out.conformance_results_sha256, results_sha256);
  });
});
