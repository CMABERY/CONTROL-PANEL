// LOCKED (archival): superseded by canonical implementations under ./replay/
//
// Retained for historical continuity only.
// Do not use for new development. Reference ./replay/*.js as canonical.

/**
 * Phase 5: Replay Index & Resolver (evidence-locked)
 *
 * Replay operates strictly over ledger artifacts already persisted by the CPO gate
 * and keyed by envelope_hash.
 *
 * The index is a deterministic view over:
 *   - accepted envelope artifacts
 *   - rejected-attempt artifacts (schema-valid rejections)
 *
 * It supports resolution by trace_id and deterministic ordering:
 *   AuthContext → PolicyDecisionRecord → Evidence (ModelCallRecord/ToolCallRecord)
 */

/**
 * @typedef {'accepted'|'rejected_attempt'} ArtifactStatus
 */

/**
 * @typedef {Object} IndexedArtifact
 * @property {ArtifactStatus} status
 * @property {string} envelope_hash
 * @property {string} record_type
 * @property {any} envelope
 * @property {string} canonical_json
 * @property {string=} classification
 * @property {string=} error_kind
 */

/**
 * @param {any} envelope
 * @returns {string|null}
 */
export function extractTraceId(envelope) {
  const t = envelope?.trace?.trace_id;
  return typeof t === 'string' ? t : null;
}

/**
 * Deterministic ordering key for an indexed artifact.
 *
 * Ordering contract:
 *   1) record_type order: auth_context < policy_decision < evidence
 *   2) per-record time key (ascending)
 *   3) envelope_hash tiebreaker (lex)
 *
 * @param {IndexedArtifact} a
 * @returns {{ typeOrder: number, timeKey: number, hash: string }}
 */
function sortKey(a) {
  const rt = a.record_type;

  let typeOrder = 99;
  let timeKey = 0;

  if (rt === 'auth_context') {
    typeOrder = 0;
    timeKey = Number(a.envelope?.ts_ms ?? 0);
  } else if (rt === 'policy_decision') {
    typeOrder = 1;
    timeKey = Number(a.envelope?.ts_ms ?? 0);
  } else if (rt === 'model_call') {
    typeOrder = 2;
    timeKey = Number(a.envelope?.started_at_ms ?? 0);
  } else if (rt === 'tool_call') {
    typeOrder = 2;
    timeKey = Number(a.envelope?.started_at_ms ?? 0);
  }

  // Reject NaN deterministically by coercing to 0.
  if (!Number.isFinite(timeKey)) timeKey = 0;

  return { typeOrder, timeKey, hash: a.envelope_hash };
}

/**
 * @param {IndexedArtifact} a
 * @param {IndexedArtifact} b
 */
function compareArtifacts(a, b) {
  const ka = sortKey(a);
  const kb = sortKey(b);
  if (ka.typeOrder !== kb.typeOrder) return ka.typeOrder - kb.typeOrder;
  if (ka.timeKey !== kb.timeKey) return ka.timeKey - kb.timeKey;
  return ka.hash.localeCompare(kb.hash);
}

/**
 * Build an index over a CPO ArtifactStore.
 *
 * @param {{accepted: Map<string, any>, rejected_attempts: Map<string, any>}} store
 * @param {{ includeRejectedAttempts?: boolean }} opts
 * @returns {{ trace_ids: string[], get: (trace_id: string) => IndexedArtifact[] }}
 */
export function buildReplayIndex(store, opts = {}) {
  const includeRejectedAttempts = opts.includeRejectedAttempts !== false;

  /** @type {Map<string, IndexedArtifact[]>} */
  const byTrace = new Map();

  for (const [hash, art] of store.accepted.entries()) {
    const trace_id = extractTraceId(art.envelope);
    if (!trace_id) continue;
    const entry = /** @type {IndexedArtifact} */ ({
      status: 'accepted',
      envelope_hash: hash,
      record_type: art.record_type,
      envelope: art.envelope,
      canonical_json: art.canonical_json,
    });
    if (!byTrace.has(trace_id)) byTrace.set(trace_id, []);
    byTrace.get(trace_id).push(entry);
  }

  if (includeRejectedAttempts) {
    for (const [hash, rej] of store.rejected_attempts.entries()) {
      const trace_id = extractTraceId(rej.envelope);
      if (!trace_id) continue;
      const entry = /** @type {IndexedArtifact} */ ({
        status: 'rejected_attempt',
        envelope_hash: hash,
        record_type: rej.record_type,
        envelope: rej.envelope,
        canonical_json: rej.canonical_json,
        classification: rej.classification,
        error_kind: rej.error_kind,
      });
      if (!byTrace.has(trace_id)) byTrace.set(trace_id, []);
      byTrace.get(trace_id).push(entry);
    }
  }

  const trace_ids = [...byTrace.keys()].sort();

  return {
    trace_ids,
    get(trace_id) {
      const entries = byTrace.get(trace_id) || [];
      return [...entries].sort(compareArtifacts);
    },
  };
}

/**
 * Resolve a deterministic accepted-only evidence chain for a trace_id.
 *
 * @param {{accepted: Map<string, any>, rejected_attempts: Map<string, any>}} store
 * @param {string} trace_id
 * @returns {{ trace_id: string, ordered: IndexedArtifact[], rejected_attempts: IndexedArtifact[] }}
 */
export function resolveChainByTraceId(store, trace_id) {
  const index = buildReplayIndex(store, { includeRejectedAttempts: true });
  const entries = index.get(trace_id);
  const ordered = entries.filter((e) => e.status === 'accepted');
  const rejected_attempts = entries.filter((e) => e.status === 'rejected_attempt');
  return { trace_id, ordered, rejected_attempts };
}
