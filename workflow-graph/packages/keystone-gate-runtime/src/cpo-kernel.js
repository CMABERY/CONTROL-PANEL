/**
 * CPO Governance Kernel (Phase 3, contract-locked)
 *
 * Implements the commit_action boundary exactly per Phase 2.
 *
 * Boundary signature: commit_action(record_type, declared_envelope_hash, envelope_object)
 *
 * Sequence (must not reorder):
 *   0. Record type allowed? (closed-world) -> RECORD_TYPE_FORBIDDEN
 *   1. Schema validation -> SCHEMA_REJECT
 *   2. Canonicalization (RFC 8785) -> canonical_json
 *   3. Hash computation -> computed_envelope_hash
 *   4. Hash comparison -> HASH_MISMATCH
 *   5. Prerequisite resolution -> MISSING_PREREQ
 *   6. Trace continuity enforcement -> TRACE_VIOLATION
 *   7. Authorization check (policy allow/deny) -> UNAUTHORIZED_EXECUTION
 *   8. Persist accepted artifact keyed by envelope_hash
 */

import {
  RECORD_TYPES,
  validateEnvelope,
  canonicalizeEnvelope,
  hashEnvelope,
} from './flowversion-envelope.js';

import {
  AcceptClass,
  FailureClass,
  NON_PERSISTENT_FAILURES,
  PERSIST_REJECTED_ATTEMPT,
  classifySchemaErrorKind,
  missingPrereqKind,
  traceViolationKind,
  unauthorizedKind,
  hashMismatchKind,
  recordTypeForbiddenKind,
} from './error-classification.js';

/**
 * @typedef {Object} StoredArtifact
 * @property {string} envelope_hash
 * @property {string} record_type
 * @property {any} envelope
 * @property {string} canonical_json
 */

/**
 * @typedef {Object} StoredRejectedAttempt
 * @property {string} envelope_hash
 * @property {string} record_type
 * @property {any} envelope
 * @property {string} canonical_json
 * @property {string} classification
 * @property {string} error_kind
 */

export class ArtifactStore {
  constructor() {
    /** @type {Map<string, StoredArtifact>} */
    this.accepted = new Map();
    /** @type {Map<string, StoredRejectedAttempt>} */
    this.rejected_attempts = new Map();
  }

  /** @param {string} envelopeHash */
  getAccepted(envelopeHash) {
    return this.accepted.get(envelopeHash) || null;
  }

  /** @param {StoredArtifact} artifact */
  putAccepted(artifact) {
    this.accepted.set(artifact.envelope_hash, artifact);
  }

  /** @param {StoredRejectedAttempt} attempt */
  putRejectedAttempt(attempt) {
    this.rejected_attempts.set(attempt.envelope_hash, attempt);
  }
}

export class CpoKernel {
  /**
   * @param {{ store?: ArtifactStore }} opts
   */
  constructor(opts = {}) {
    this.store = opts.store || new ArtifactStore();
  }

  /**
   * commit_action(record_type, declared_envelope_hash, envelope_object)
   *
   * @param {string} record_type
   * @param {string} declared_envelope_hash
   * @param {any} envelope
   * @returns {{ ok: true, classification: typeof AcceptClass, envelope_hash: string, canonical_json: string } | { ok: false, classification: string, error_kind: string, computed_envelope_hash?: string, canonical_json?: string }}
   */
  commit_action(record_type, declared_envelope_hash, envelope) {
    // 0) Closed-world record type check.
    if (!RECORD_TYPES.includes(record_type)) {
      return {
        ok: false,
        classification: FailureClass.RECORD_TYPE_FORBIDDEN,
        error_kind: recordTypeForbiddenKind(),
      };
    }

    // 1) Schema validation.
    const v = validateEnvelope(envelope);
    if (!v.ok) {
      return {
        ok: false,
        classification: FailureClass.SCHEMA_REJECT,
        error_kind: classifySchemaErrorKind(v.errors),
      };
    }

    // Fail-closed: the boundary-declared record_type must match the envelope payload.
    // Treat mismatch as a schema rejection (contract breach).
    if (envelope?.record_type !== record_type) {
      return {
        ok: false,
        classification: FailureClass.SCHEMA_REJECT,
        error_kind: 'schema_violation.record_type_mismatch',
      };
    }

    // 2) Canonicalization.
    const canonical_json = canonicalizeEnvelope(envelope);

    // 3) Hash computation.
    const computed_envelope_hash = hashEnvelope(envelope);

    // 4) Hash comparison.
    if (declared_envelope_hash !== computed_envelope_hash) {
      const classification = FailureClass.HASH_MISMATCH;
      const error_kind = hashMismatchKind();

      this._persistRejectedAttemptIfRequired({
        classification,
        error_kind,
        record_type,
        envelope,
        canonical_json,
        envelope_hash: computed_envelope_hash,
      });

      return {
        ok: false,
        classification,
        error_kind,
        computed_envelope_hash,
        canonical_json,
      };
    }

    // 5) Prerequisite resolution.
    const prereqs = this._resolvePrereqs(record_type, envelope);
    if (!prereqs.ok) {
      this._persistRejectedAttemptIfRequired({
        classification: prereqs.classification,
        error_kind: prereqs.error_kind,
        record_type,
        envelope,
        canonical_json,
        envelope_hash: computed_envelope_hash,
      });

      return {
        ok: false,
        classification: prereqs.classification,
        error_kind: prereqs.error_kind,
        computed_envelope_hash,
        canonical_json,
      };
    }

    // 6) Trace continuity enforcement.
    const traceOk = this._enforceTraceContinuity(record_type, envelope, prereqs);
    if (!traceOk.ok) {
      this._persistRejectedAttemptIfRequired({
        classification: traceOk.classification,
        error_kind: traceOk.error_kind,
        record_type,
        envelope,
        canonical_json,
        envelope_hash: computed_envelope_hash,
      });

      return {
        ok: false,
        classification: traceOk.classification,
        error_kind: traceOk.error_kind,
        computed_envelope_hash,
        canonical_json,
      };
    }

    // 7) Authorization check.
    const authzOk = this._enforceAuthorization(record_type, prereqs);
    if (!authzOk.ok) {
      this._persistRejectedAttemptIfRequired({
        classification: authzOk.classification,
        error_kind: authzOk.error_kind,
        record_type,
        envelope,
        canonical_json,
        envelope_hash: computed_envelope_hash,
      });

      return {
        ok: false,
        classification: authzOk.classification,
        error_kind: authzOk.error_kind,
        computed_envelope_hash,
        canonical_json,
      };
    }

    // 8) Persist accepted artifact.
    this.store.putAccepted({
      envelope_hash: computed_envelope_hash,
      record_type,
      envelope,
      canonical_json,
    });

    return {
      ok: true,
      classification: AcceptClass,
      envelope_hash: computed_envelope_hash,
      canonical_json,
    };
  }

  /**
   * @param {{classification: string, error_kind: string, record_type: string, envelope: any, canonical_json: string, envelope_hash: string}} x
   */
  _persistRejectedAttemptIfRequired(x) {
    if (NON_PERSISTENT_FAILURES.has(x.classification)) return;
    if (!PERSIST_REJECTED_ATTEMPT.has(x.classification)) return;

    this.store.putRejectedAttempt({
      envelope_hash: x.envelope_hash,
      record_type: x.record_type,
      envelope: x.envelope,
      canonical_json: x.canonical_json,
      classification: x.classification,
      error_kind: x.error_kind,
    });
  }

  /**
   * @param {string} record_type
   * @param {any} envelope
   */
  _resolvePrereqs(record_type, envelope) {
    if (record_type === 'auth_context') return { ok: true };

    if (record_type === 'policy_decision') {
      const h = envelope.auth_context_envelope_sha256;
      const auth = this.store.getAccepted(h);
      if (!auth) {
        return { ok: false, classification: FailureClass.MISSING_PREREQ, error_kind: missingPrereqKind('auth_context') };
      }
      return { ok: true, auth_context: auth };
    }

    if (record_type === 'model_call' || record_type === 'tool_call') {
      const authHash = envelope.auth_context_envelope_sha256;
      const pdHash = envelope.policy_decision_envelope_sha256;

      const auth = this.store.getAccepted(authHash);
      if (!auth) {
        return { ok: false, classification: FailureClass.MISSING_PREREQ, error_kind: missingPrereqKind('auth_context') };
      }
      const pd = this.store.getAccepted(pdHash);
      if (!pd) {
        return { ok: false, classification: FailureClass.MISSING_PREREQ, error_kind: missingPrereqKind('policy_decision') };
      }
      return { ok: true, auth_context: auth, policy_decision: pd };
    }

    // Should not happen due to RECORD_TYPES gate.
    return { ok: false, classification: FailureClass.RECORD_TYPE_FORBIDDEN, error_kind: recordTypeForbiddenKind() };
  }

  /**
   * @param {string} record_type
   * @param {any} envelope
   * @param {any} prereqs
   */
  _enforceTraceContinuity(record_type, envelope, prereqs) {
    if (record_type === 'auth_context') return { ok: true };

    const traceId = envelope?.trace?.trace_id;
    if (typeof traceId !== 'string') {
      // Should be schema-impossible, but fail-closed.
      return { ok: false, classification: FailureClass.TRACE_VIOLATION, error_kind: traceViolationKind() };
    }

    // PolicyDecisionRecord must match AuthContext trace_id.
    if (record_type === 'policy_decision') {
      const authTrace = prereqs.auth_context?.envelope?.trace?.trace_id;
      if (authTrace !== traceId) {
        return { ok: false, classification: FailureClass.TRACE_VIOLATION, error_kind: traceViolationKind() };
      }
      return { ok: true };
    }

    // Model/Tool call must match both prereqs.
    if (record_type === 'model_call' || record_type === 'tool_call') {
      const authTrace = prereqs.auth_context?.envelope?.trace?.trace_id;
      const pdTrace = prereqs.policy_decision?.envelope?.trace?.trace_id;
      if (authTrace !== traceId || pdTrace !== traceId) {
        return { ok: false, classification: FailureClass.TRACE_VIOLATION, error_kind: traceViolationKind() };
      }
      return { ok: true };
    }

    return { ok: true };
  }

  /**
   * @param {string} record_type
   * @param {any} prereqs
   */
  _enforceAuthorization(record_type, prereqs) {
    if (record_type !== 'model_call' && record_type !== 'tool_call') return { ok: true };

    const pd = prereqs.policy_decision;
    const result = pd?.envelope?.decision?.result;
    if (result !== 'allow') {
      return { ok: false, classification: FailureClass.UNAUTHORIZED_EXECUTION, error_kind: unauthorizedKind() };
    }

    return { ok: true };
  }
}
