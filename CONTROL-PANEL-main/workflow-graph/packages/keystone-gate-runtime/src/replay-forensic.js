// LOCKED (archival): superseded by canonical implementations under ./replay/
//
// Retained for historical continuity only.
// Do not use for new development. Reference ./replay/*.js as canonical.

/**
 * Phase 5 Replay Plumbing: Forensic Replay (bit-exact)
 *
 * Forensic replay is the strongest mode:
 * - operates on accepted ledger artifacts
 * - re-validates schema
 * - re-canonicalizes (RFC 8785/JCS)
 * - re-hashes and matches envelope_hash
 * - re-submits the same envelopes through a fresh CPO gate instance
 *   to prove identical accept outcomes under identical canonicalization
 *
 * Fail-closed:
 * - any mismatch (schema, canonical, hash, prereq, trace, authz) fails.
 */

import assert from 'node:assert/strict';
import { validateEnvelope, canonicalizeEnvelope, hashEnvelope } from './flowversion-envelope.js';
import { CpoKernel, ArtifactStore } from './cpo-kernel.js';
import { FailureClass, AcceptClass } from './error-classification.js';
import { ReplayIndex } from './replay-index.js';
import { emitReplayResult } from './replay-results.js';

function deepClone(x) {
  return JSON.parse(JSON.stringify(x));
}

/**
 * @param {any} store
 * @param {string} trace_id
 * @param {{ now_ms?: number }} opts
 */
export function forensicReplay(store, trace_id, opts = {}) {
  const now_ms = opts.now_ms ?? Date.now();

  const index = new ReplayIndex(store).build();

  // Forensic replay is defined over ACCEPTED artifacts.
  const chain_time = index.resolve(trace_id, { includeRejected: false, order: 'time' });
  const chain_display = index.resolve(trace_id, { includeRejected: false, order: 'display' });

  /** @type {any} */
  const replayRecordBase = {
    replay_type: 'forensic',
    target_trace_id: trace_id,
    input_envelope_hashes: chain_display.map((p) => p.envelope_hash),
    generated_at: now_ms,
  };

  if (chain_time.length === 0) {
    const rec = {
      ...replayRecordBase,
      result: 'fail',
      failure_class: FailureClass.MISSING_PREREQ,
      error_kind: 'replay.not_found',
    };
    const out = emitReplayResult(store, rec);
    return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
  }

  // Fresh gate instance + fresh store: ensures replay proves behavior, not current ledger state.
  const replayKernel = new CpoKernel({ store: new ArtifactStore() });

  for (const p of chain_time) {
    // 1) Schema must still validate.
    const v = validateEnvelope(p.envelope);
    if (!v.ok) {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: FailureClass.SCHEMA_REJECT,
        error_kind: 'replay.schema_invalid_in_ledger',
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }

    // 2) Canonical JSON must match stored canonical bytes.
    const canon = canonicalizeEnvelope(p.envelope);
    if (canon !== p.canonical_json) {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        error_kind: 'replay.canonical_json_mismatch',
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }

    // 3) Recomputed hash must match stored envelope_hash.
    const h = hashEnvelope(p.envelope);
    if (h !== p.envelope_hash) {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        error_kind: 'replay.envelope_hash_mismatch',
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash, recomputed: h },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }

    // 4) Re-submit through a fresh gate instance.
    const res = replayKernel.commit_action(p.record_type, p.envelope_hash, deepClone(p.envelope));
    if (!res.ok) {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: res.classification,
        error_kind: res.error_kind,
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }

    // Bit-exact: gate output must match stored.
    try {
      assert.equal(res.classification, AcceptClass);
      assert.equal(res.envelope_hash, p.envelope_hash);
      assert.equal(res.canonical_json, p.canonical_json);
    } catch {
      const rec = {
        ...replayRecordBase,
        result: 'fail',
        failure_class: FailureClass.HASH_MISMATCH,
        error_kind: 'replay.gate_output_mismatch',
        details: { record_type: p.record_type, envelope_hash: p.envelope_hash },
      };
      const out = emitReplayResult(store, rec);
      return { ok: false, ...rec, replay_result_sha256: out.replay_result_sha256 };
    }
  }

  const rec = {
    ...replayRecordBase,
    result: 'pass',
  };
  const out = emitReplayResult(store, rec);
  return { ok: true, ...rec, replay_result_sha256: out.replay_result_sha256 };
}
