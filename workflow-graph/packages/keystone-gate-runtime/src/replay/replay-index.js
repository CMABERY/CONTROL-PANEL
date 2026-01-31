/**
 * Replay Index & Resolver (Phase 5, evidence-locked)
 *
 * Replay operates over ledger artifacts already persisted by the CPO gate.
 *
 * Index responsibilities:
 * - resolve evidence by trace_id
 * - order deterministically: AuthContext -> PolicyDecisionRecord -> Evidence (ModelCall/ToolCall)
 * - include accepted artifacts and (optionally) rejected-attempt artifacts
 */

/**
 * @typedef {'accepted'|'rejected_attempt'} LedgerStatus
 */

/**
 * @typedef {Object} LedgerEnvelopeArtifact
 * @property {string} envelope_hash
 * @property {'auth_context'|'policy_decision'|'model_call'|'tool_call'} record_type
 * @property {any} envelope
 * @property {string} canonical_json
 * @property {LedgerStatus} ledger_status
 * @property {string=} classification
 * @property {string=} error_kind
 */

/**
 * @typedef {Object} ResolvedTraceChain
 * @property {string} trace_id
 * @property {LedgerEnvelopeArtifact[]} ordered
 * @property {LedgerEnvelopeArtifact[]} auth_context
 * @property {LedgerEnvelopeArtifact[]} policy_decision
 * @property {LedgerEnvelopeArtifact[]} evidence
 */

function getTraceId(envelope) {
  return envelope?.trace?.trace_id;
}

function recordRank(rt) {
  switch (rt) {
    case 'auth_context':
      return 0;
    case 'policy_decision':
      return 1;
    case 'model_call':
    case 'tool_call':
      return 2;
    default:
      return 9;
  }
}

function timeKey(artifact) {
  const e = artifact.envelope;
  if (artifact.record_type === 'auth_context' || artifact.record_type === 'policy_decision') {
    return typeof e?.ts_ms === 'number' ? e.ts_ms : 0;
  }
  if (artifact.record_type === 'model_call' || artifact.record_type === 'tool_call') {
    return typeof e?.started_at_ms === 'number' ? e.started_at_ms : 0;
  }
  return 0;
}

/**
 * Build a trace index over an ArtifactStore.
 *
 * @param {any} store
 * @param {{ include_rejected_attempts?: boolean }} opts
 * @returns {Map<string, LedgerEnvelopeArtifact[]>}
 */
export function buildTraceIndex(store, opts = {}) {
  const includeRejected = opts.include_rejected_attempts === true;

  /** @type {Map<string, LedgerEnvelopeArtifact[]>} */
  const idx = new Map();

  /** @param {LedgerEnvelopeArtifact} art */
  function add(art) {
    const tid = getTraceId(art.envelope);
    if (typeof tid !== 'string' || tid.length === 0) return;
    const arr = idx.get(tid) || [];
    arr.push(art);
    idx.set(tid, arr);
  }

  for (const [h, a] of store.accepted.entries()) {
    add({
      envelope_hash: h,
      record_type: a.record_type,
      envelope: a.envelope,
      canonical_json: a.canonical_json,
      ledger_status: 'accepted',
    });
  }

  if (includeRejected) {
    for (const [h, a] of store.rejected_attempts.entries()) {
      add({
        envelope_hash: h,
        record_type: a.record_type,
        envelope: a.envelope,
        canonical_json: a.canonical_json,
        ledger_status: 'rejected_attempt',
        classification: a.classification,
        error_kind: a.error_kind,
      });
    }
  }

  return idx;
}

/**
 * Resolve a deterministic chain view for a trace_id.
 *
 * Ordering rule (normative for replay):
 * - primary: record class (AuthContext -> PolicyDecision -> Evidence)
 * - secondary: time (ts_ms or started_at_ms)
 * - tertiary: envelope_hash lex
 *
 * @param {any} store
 * @param {string} trace_id
 * @param {{ include_rejected_attempts?: boolean }} opts
 * @returns {ResolvedTraceChain | null}
 */
export function resolveTraceChain(store, trace_id, opts = {}) {
  const idx = buildTraceIndex(store, { include_rejected_attempts: opts.include_rejected_attempts === true });
  const items = idx.get(trace_id);
  if (!items || items.length === 0) return null;

  const ordered = [...items].sort((a, b) => {
    const ra = recordRank(a.record_type);
    const rb = recordRank(b.record_type);
    if (ra !== rb) return ra - rb;
    const ta = timeKey(a);
    const tb = timeKey(b);
    if (ta !== tb) return ta - tb;
    return a.envelope_hash.localeCompare(b.envelope_hash);
  });

  const auth_context = ordered.filter((x) => x.record_type === 'auth_context');
  const policy_decision = ordered.filter((x) => x.record_type === 'policy_decision');
  const evidence = ordered.filter((x) => x.record_type === 'model_call' || x.record_type === 'tool_call');

  return { trace_id, ordered, auth_context, policy_decision, evidence };
}
