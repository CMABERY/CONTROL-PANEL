/**
 * Phase 2 Failure Taxonomy (locked) + deterministic error_kind mapping.
 */

export const FailureClass = /** @type {const} */ ({
  SCHEMA_REJECT: 'SCHEMA_REJECT',
  HASH_MISMATCH: 'HASH_MISMATCH',
  MISSING_PREREQ: 'MISSING_PREREQ',
  TRACE_VIOLATION: 'TRACE_VIOLATION',
  UNAUTHORIZED_EXECUTION: 'UNAUTHORIZED_EXECUTION',
  RECORD_TYPE_FORBIDDEN: 'RECORD_TYPE_FORBIDDEN',
});

export const AcceptClass = /** @type {const} */ ('ACCEPT');

/**
 * Errors of this class MUST NOT be persisted as ledger artifacts because
 * canonical bytes + envelope_hash are undefined by rule.
 */
export const NON_PERSISTENT_FAILURES = new Set([FailureClass.SCHEMA_REJECT]);

/**
 * Failures that MUST be persisted as rejected-attempt ledger artifacts
 * (only when schema-valid, because canonical bytes exist).
 */
export const PERSIST_REJECTED_ATTEMPT = new Set([
  FailureClass.HASH_MISMATCH,
  FailureClass.MISSING_PREREQ,
  FailureClass.TRACE_VIOLATION,
  FailureClass.UNAUTHORIZED_EXECUTION,
]);

/**
 * Deterministic schema error-kind extractor.
 *
 * This is intentionally narrow: it emits stable strings used by integration tests,
 * not a full diagnostic surface.
 *
 * @param {any[]} ajvErrors
 * @returns {string}
 */
export function classifySchemaErrorKind(ajvErrors) {
  if (!Array.isArray(ajvErrors) || ajvErrors.length === 0) {
    return 'schema_violation.unknown';
  }

  // Prefer the first error (Ajv ordering is stable for a fixed schema + input).
  const e = ajvErrors[0] || {};

  if (e.keyword === 'required') {
    const missing = e.params?.missingProperty;
    if (missing === 'trace_id' && (e.instancePath === '/trace' || e.instancePath?.endsWith('/trace'))) {
      return 'schema_violation.trace_context.missing_trace_id';
    }
    if (typeof missing === 'string') {
      return `schema_violation.required.${missing}`;
    }
    return 'schema_violation.required';
  }

  if (e.keyword === 'additionalProperties') {
    return 'schema_violation.additional_properties';
  }

  if (e.keyword === 'type') {
    return 'schema_violation.type';
  }

  if (e.keyword === 'pattern') {
    return 'schema_violation.pattern';
  }

  if (e.keyword === 'enum') {
    return 'schema_violation.enum';
  }

  return `schema_violation.${String(e.keyword || 'unknown')}`;
}

/**
 * Deterministic prereq missing error kind.
 * @param {'auth_context'|'policy_decision'} prereq
 * @returns {string}
 */
export function missingPrereqKind(prereq) {
  return prereq === 'auth_context'
    ? 'missing_prereq.auth_context'
    : 'missing_prereq.policy_decision';
}

export function traceViolationKind() {
  return 'trace_violation.trace_id_mismatch';
}

export function unauthorizedKind() {
  return 'unauthorized.policy_denied';
}

export function hashMismatchKind() {
  return 'hash_mismatch.envelope_hash';
}

export function recordTypeForbiddenKind() {
  return 'record_type_forbidden';
}
