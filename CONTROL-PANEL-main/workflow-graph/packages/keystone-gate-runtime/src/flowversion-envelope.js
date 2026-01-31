/**
 * FlowVersion Envelope Operations (Phase 3, contract-locked)
 *
 * Determinism contract:
 * - validateEnvelope(envelope): JSON Schema (Draft 2020-12), fail-closed
 * - canonicalizeEnvelope(envelope): RFC 8785 (JCS) canonical JSON string
 * - hashEnvelope(envelope): SHA-256 over UTF-8 canonical JSON bytes (lowercase hex)
 *
 * Note: Schema gating is required before canonicalization/hashing at boundaries.
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(__dirname, '..', 'schemas');

const SCHEMA_FILES = [
  'Shared.schema.json',
  'TraceContext.schema.json',
  'AuthContext.schema.json',
  'PolicyDecisionRecord.schema.json',
  'ModelCallRecord.schema.json',
  'ToolCallRecord.schema.json',
];

/**
 * Record types supported by the locked Phase 1 schema pack.
 * @type {const}
 */
export const RECORD_TYPES = /** @type {const} */ ([
  'auth_context',
  'policy_decision',
  'model_call',
  'tool_call',
]);

/**
 * Load and compile validators once.
 */
function buildRegistry() {
  /** @type {any[]} */
  const schemas = SCHEMA_FILES.map((f) => JSON.parse(readFileSync(join(SCHEMA_DIR, f), 'utf8')));

  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);

  // Add all schemas to resolve cross-file refs.
  for (const s of schemas) ajv.addSchema(s);

  const ids = new Map(schemas.map((s) => [s.$id, s]));

  const schemaIdByRecordType = {
    auth_context: ids.get('https://control-panel.local/schemas/keystone/AuthContext.schema.json').$id,
    policy_decision: ids.get('https://control-panel.local/schemas/keystone/PolicyDecisionRecord.schema.json').$id,
    model_call: ids.get('https://control-panel.local/schemas/keystone/ModelCallRecord.schema.json').$id,
    tool_call: ids.get('https://control-panel.local/schemas/keystone/ToolCallRecord.schema.json').$id,
  };

  /** @type {Record<string, import('ajv').ValidateFunction>} */
  const validators = {};
  for (const [rt, sid] of Object.entries(schemaIdByRecordType)) {
    validators[rt] = ajv.getSchema(sid);
    if (!validators[rt]) {
      throw new Error(`Missing compiled schema for record_type=${rt} ($id=${sid})`);
    }
  }

  return { ajv, validators };
}

const _REGISTRY = buildRegistry();

/**
 * Validate an envelope against the Phase 1 schema pack.
 *
 * Fail-closed behavior:
 * - Unknown record_type is invalid (no schema selection).
 * - Unknown fields fail because schemas are closed-world.
 *
 * @param {unknown} envelope
 * @returns {{ ok: true, record_type: typeof RECORD_TYPES[number] } | { ok: false, record_type?: string, errors: any[] }}
 */
export function validateEnvelope(envelope) {
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return { ok: false, errors: [{ keyword: 'type', message: 'must be object', instancePath: '' }] };
  }

  // @ts-ignore
  const recordType = envelope.record_type;
  if (typeof recordType !== 'string') {
    return {
      ok: false,
      record_type: undefined,
      errors: [{ keyword: 'required', message: 'missing record_type', instancePath: '', params: { missingProperty: 'record_type' } }],
    };
  }

  if (!RECORD_TYPES.includes(recordType)) {
    return {
      ok: false,
      record_type: recordType,
      errors: [{ keyword: 'enum', message: 'unknown record_type', instancePath: '/record_type', params: { allowedValues: RECORD_TYPES } }],
    };
  }

  const validate = _REGISTRY.validators[recordType];
  const ok = validate(envelope);
  if (!ok) {
    return { ok: false, record_type: recordType, errors: validate.errors ?? [] };
  }

  return { ok: true, record_type: recordType };
}

/**
 * RFC 8785 / JCS canonical JSON serialization.
 *
 * Important restrictions (Phase 1):
 * - Numbers MUST be integers only and within JS safe integer range.
 * - Undefined is forbidden.
 *
 * This serializer is sufficient for the Phase 1 envelope schemas because:
 * - Object keys are ASCII (schema-constrained), so JS lex sort matches codepoint order.
 * - Numbers are integer-only.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalizeEnvelope(value) {
  return jcsSerialize(value);
}

/**
 * Compute the envelope hash.
 * @param {unknown} envelope
 * @returns {string} lowercase hex sha256
 */
export function hashEnvelope(envelope) {
  const canonical = canonicalizeEnvelope(envelope);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

// -------------------------
// JCS serializer (minimal)
// -------------------------

/**
 * @param {unknown} v
 * @returns {string}
 */
function jcsSerialize(v) {
  if (v === null) return 'null';

  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'string') return JSON.stringify(v);

  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error('Non-finite numbers are forbidden in canonical JSON');
    // JCS allows floats, but Phase 1 forbids them.
    if (!Number.isInteger(v)) throw new Error('Non-integer numbers are forbidden in canonical JSON');
    if (!Number.isSafeInteger(v)) throw new Error('Unsafe integers are forbidden in canonical JSON');
    // Handle -0 explicitly.
    if (Object.is(v, -0)) return '0';
    return String(v);
  }

  if (t === 'undefined') {
    throw new Error('Undefined is forbidden in canonical JSON');
  }

  if (Array.isArray(v)) {
    return '[' + v.map(jcsSerialize).join(',') + ']';
  }

  if (t === 'object') {
    // plain object expected
    const obj = /** @type {Record<string, unknown>} */ (v);
    const keys = Object.keys(obj).sort();
    let out = '{';
    let first = true;
    for (const k of keys) {
      const val = obj[k];
      if (typeof val === 'undefined') {
        throw new Error('Undefined is forbidden in canonical JSON');
      }
      if (!first) out += ',';
      first = false;
      out += JSON.stringify(k) + ':' + jcsSerialize(val);
    }
    out += '}';
    return out;
  }

  throw new Error(`Unsupported type in canonical JSON: ${t}`);
}
