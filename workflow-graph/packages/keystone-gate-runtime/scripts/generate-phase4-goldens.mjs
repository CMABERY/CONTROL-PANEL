/**
 * Phase 4: generate golden conformance vectors.
 *
 * Determinism:
 * - All fixtures are fixed.
 * - Canonicalization/hashing are performed by FlowVersion envelope ops.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { canonicalizeEnvelope, hashEnvelope, validateEnvelope } from '../src/flowversion-envelope.js';
import {
  produceAuthContext_A,
  produceAuthContext_B,
  produceModelCall_A,
  produceModelCall_B,
  producePolicyDecisionAllow_Model,
  producePolicyDecisionAllow_Tool,
  producePolicyDecisionDeny_Tool,
  produceToolCall_A,
  produceToolCall_B,
  hashEnvelopeWrong_Stringify
} from '../src/conformance-producers.js';

function sha256Utf8(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function vectorSameEnvelope(name, a, b) {
  const va = validateEnvelope(a);
  const vb = validateEnvelope(b);
  if (!va.ok || !vb.ok) {
    throw new Error(`Fixture invalid: ${name}`);
  }

  const canon = canonicalizeEnvelope(a);
  const ha = hashEnvelope(a);
  const hb = hashEnvelope(b);
  const canonB = canonicalizeEnvelope(b);

  if (canon !== canonB) {
    throw new Error(`Canonical mismatch for ${name}`);
  }
  if (ha !== hb) {
    throw new Error(`Hash mismatch for ${name}`);
  }

  return {
    name,
    expectation: { overall: 'accept' },
    setup: null,
    producer_variants: [
      { producer_id: 'A', input: a, declared_envelope_hash: ha },
      { producer_id: 'B', input: b, declared_envelope_hash: hb }
    ],
    canonical_json: canon,
    sha256: ha
  };
}

function vectorSameEnvelopeRejected(name, a, b, classification, error_kind) {
  const va = validateEnvelope(a);
  const vb = validateEnvelope(b);
  if (!va.ok || !vb.ok) {
    throw new Error(`Fixture invalid: ${name}`);
  }

  const canon = canonicalizeEnvelope(a);
  const ha = hashEnvelope(a);
  const hb = hashEnvelope(b);
  const canonB = canonicalizeEnvelope(b);

  if (canon !== canonB) throw new Error(`Canonical mismatch for ${name}`);
  if (ha !== hb) throw new Error(`Hash mismatch for ${name}`);

  return {
    name,
    expectation: { overall: 'reject', classification, error_kind },
    setup: null,
    producer_variants: [
      { producer_id: 'A', input: a, declared_envelope_hash: ha },
      { producer_id: 'B', input: b, declared_envelope_hash: hb }
    ],
    canonical_json: canon,
    sha256: ha
  };
}

function vectorHashDrift(name, envelope) {
  const v = validateEnvelope(envelope);
  if (!v.ok) throw new Error(`Fixture invalid: ${name}`);

  const correct = hashEnvelope(envelope);
  const wrong = hashEnvelopeWrong_Stringify(envelope);

  return {
    name,
    expectation: { overall: 'reject', classification: 'HASH_MISMATCH' },
    setup: null,
    input: envelope,
    canonical_json: canonicalizeEnvelope(envelope),
    computed_sha256: correct,
    declared_envelope_hash: wrong,
    wrong_hash_sha256: wrong
  };
}

function vectorSchemaReject(name, envelope) {
  const v = validateEnvelope(envelope);
  if (v.ok) throw new Error(`Fixture expected invalid but validated: ${name}`);
  return {
    name,
    expectation: { overall: 'reject', classification: 'SCHEMA_REJECT' },
    setup: null,
    input: envelope,
    canonical_json: null,
    sha256: null
  };
}

// -------------------------
// Build vectors
// -------------------------

const authA = produceAuthContext_A();
const authB = produceAuthContext_B();

const authHash = hashEnvelope(authA);

const pdTool = producePolicyDecisionAllow_Tool(authHash);
const pdToolHash = hashEnvelope(pdTool);

const tcA = produceToolCall_A(authHash, pdToolHash);
const tcB = produceToolCall_B(authHash, pdToolHash);

const pdModel = producePolicyDecisionAllow_Model(authHash);
const pdModelHash = hashEnvelope(pdModel);

const mcA = produceModelCall_A(authHash, pdModelHash);
const mcB = produceModelCall_B(authHash, pdModelHash);

// Missing prereq variant: policy hash points to a non-existent artifact.
const missingPolicyHash = '9'.repeat(64);
const tcMissingPolicyA = produceToolCall_A(authHash, missingPolicyHash);
const tcMissingPolicyB = produceToolCall_B(authHash, missingPolicyHash);

// Trace violation variant: trace_id differs from prereqs.
const tcTraceBadA = produceToolCall_A(authHash, pdToolHash);
tcTraceBadA.trace.trace_id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const tcTraceBadB = produceToolCall_B(authHash, pdToolHash);
tcTraceBadB.trace.trace_id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

// PolicyDecisionRecord missing AuthContext prerequisite (runtime gate, not schema).
const missingAuthHash = '1'.repeat(64);
const pdMissingAuth = producePolicyDecisionAllow_Tool(missingAuthHash);
{
  const v = validateEnvelope(pdMissingAuth);
  if (!v.ok) throw new Error('Fixture invalid: policy_decision_missing_auth_prereq');
}
const pdMissingAuthCanon = canonicalizeEnvelope(pdMissingAuth);
const pdMissingAuthHash = hashEnvelope(pdMissingAuth);

// Unauthorized execution variant: points to a deny policy decision.
const pdDeny = producePolicyDecisionDeny_Tool(authHash);
const pdDenyHash = hashEnvelope(pdDeny);
const tcUnauthorizedA = produceToolCall_A(authHash, pdDenyHash);
const tcUnauthorizedB = produceToolCall_B(authHash, pdDenyHash);

const badExtra = { ...produceAuthContext_A(), extra: 1 };
const badTrace = produceAuthContext_A();
delete badTrace.trace.trace_id;

const vectors = [
  (() => {
    const v = vectorSameEnvelope('same_envelope_auth_context_key_order', authA, authB);
    return v;
  })(),

  (() => {
    const v = vectorSameEnvelope('same_envelope_tool_call_key_order', tcA, tcB);
    v.setup = {
      accepted_prereqs: [
        { record_type: 'auth_context', input: authA, canonical_json: canonicalizeEnvelope(authA), sha256: authHash },
        { record_type: 'policy_decision', input: pdTool, canonical_json: canonicalizeEnvelope(pdTool), sha256: pdToolHash }
      ]
    };
    return v;
  })(),

  (() => {
    const v = vectorSameEnvelope('same_envelope_model_call_key_order', mcA, mcB);
    v.setup = {
      accepted_prereqs: [
        { record_type: 'auth_context', input: authA, canonical_json: canonicalizeEnvelope(authA), sha256: authHash },
        { record_type: 'policy_decision', input: pdModel, canonical_json: canonicalizeEnvelope(pdModel), sha256: pdModelHash }
      ]
    };
    return v;
  })(),

  {
    name: 'policy_decision_missing_auth_prereq',
    expectation: {
      overall: 'reject',
      classification: 'MISSING_PREREQ',
      error_kind: 'missing_prereq.auth_context'
    },
    setup: null,
    record_type: 'policy_decision',
    input: pdMissingAuth,
    declared_envelope_hash: pdMissingAuthHash,
    canonical_json: pdMissingAuthCanon,
    sha256: pdMissingAuthHash
  },

  (() => {
    const v = vectorHashDrift('declared_hash_drift_rejected', tcA);
    v.setup = {
      accepted_prereqs: [
        { record_type: 'auth_context', input: authA, canonical_json: canonicalizeEnvelope(authA), sha256: authHash },
        { record_type: 'policy_decision', input: pdTool, canonical_json: canonicalizeEnvelope(pdTool), sha256: pdToolHash }
      ]
    };
    return v;
  })(),

  (() => {
    const v = vectorSameEnvelopeRejected(
      'missing_prereq_policy_decision',
      tcMissingPolicyA,
      tcMissingPolicyB,
      'MISSING_PREREQ',
      'missing_prereq.policy_decision'
    );
    v.setup = {
      accepted_prereqs: [
        { record_type: 'auth_context', input: authA, canonical_json: canonicalizeEnvelope(authA), sha256: authHash }
      ]
    };
    return v;
  })(),

  (() => {
    const v = vectorSameEnvelopeRejected(
      'trace_violation_trace_id_mismatch',
      tcTraceBadA,
      tcTraceBadB,
      'TRACE_VIOLATION',
      'trace_violation.trace_id_mismatch'
    );
    v.setup = {
      accepted_prereqs: [
        { record_type: 'auth_context', input: authA, canonical_json: canonicalizeEnvelope(authA), sha256: authHash },
        { record_type: 'policy_decision', input: pdTool, canonical_json: canonicalizeEnvelope(pdTool), sha256: pdToolHash }
      ]
    };
    return v;
  })(),

  (() => {
    const v = vectorSameEnvelopeRejected(
      'unauthorized_execution_policy_denied',
      tcUnauthorizedA,
      tcUnauthorizedB,
      'UNAUTHORIZED_EXECUTION',
      'unauthorized.policy_denied'
    );
    v.setup = {
      accepted_prereqs: [
        { record_type: 'auth_context', input: authA, canonical_json: canonicalizeEnvelope(authA), sha256: authHash },
        { record_type: 'policy_decision', input: pdDeny, canonical_json: canonicalizeEnvelope(pdDeny), sha256: pdDenyHash }
      ]
    };
    return v;
  })(),

  (() => {
    const v = vectorSchemaReject('schema_reject_extra_field', badExtra);
    return v;
  })(),

  (() => {
    const v = vectorSchemaReject('schema_reject_missing_trace_id', badTrace);
    return v;
  })()
];

// Suite manifest hash: hash of canonical JSON for the vectors themselves.
const suiteManifest = {
  spec_version: '1.0.0',
  canon_version: '1',
  suite_name: 'phase4.cross_layer_conformance',
  suite_version: '1',
  vectors
};

const suiteCanonical = canonicalizeEnvelope(suiteManifest);
const suite_sha256 = sha256Utf8(suiteCanonical);

const out = {
  _meta: {
    spec_version: '1.0.0',
    canon_version: '1',
    generated_at: '2026-01-31T00:00:00Z',
    generator: 'scripts/generate-phase4-goldens.mjs',
    suite_sha256
  },
  suite: {
    name: suiteManifest.suite_name,
    version: suiteManifest.suite_version
  },
  vectors
};

mkdirSync('goldens', { recursive: true });
writeFileSync(join('goldens', 'conformance.goldens.json'), JSON.stringify(out, null, 2) + '\n', 'utf8');

console.log(`Wrote goldens/conformance.goldens.json`);
console.log(`suite_sha256=${suite_sha256}`);
