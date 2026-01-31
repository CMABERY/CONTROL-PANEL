/**
 * Replay failure classification (Phase 5).
 *
 * Reuses Phase 2 failure classes where applicable, and adds replay-specific
 * classifications for equivalence checks.
 */

import { FailureClass } from '../error-classification.js';

/**
 * Failures that map directly to Phase 2 taxonomy.
 */
export const ReplayFailure = /** @type {const} */ ({
  // Direct mappings
  SCHEMA_REJECT: FailureClass.SCHEMA_REJECT,
  HASH_MISMATCH: FailureClass.HASH_MISMATCH,
  MISSING_PREREQ: FailureClass.MISSING_PREREQ,
  TRACE_VIOLATION: FailureClass.TRACE_VIOLATION,
  UNAUTHORIZED_EXECUTION: FailureClass.UNAUTHORIZED_EXECUTION,

  // Replay-specific
  CHAIN_NOT_FOUND: 'REPLAY_CHAIN_NOT_FOUND',
  POLICY_PATH_MISMATCH: 'REPLAY_POLICY_PATH_MISMATCH',
  VARIANCE_VIOLATION: 'REPLAY_VARIANCE_VIOLATION',
});
