/**
 * Replay Ledger
 *
 * Phase 5 adds replay result artifacts as content-addressed ledger artifacts.
 * This does not introduce any new envelope record types.
 */

import { ArtifactStore } from '../cpo-kernel.js';

/**
 * Ledger extends the Phase 3 ArtifactStore with a replay-results namespace.
 */
export class Ledger extends ArtifactStore {
  constructor() {
    super();
    /** @type {Map<string, {artifact_hash: string, canonical_json: string, artifact: any}>} */
    this.replay_results = new Map();
  }

  /**
   * @param {string} artifact_hash
   * @param {string} canonical_json
   * @param {any} artifact
   */
  putReplayResult(artifact_hash, canonical_json, artifact) {
    this.replay_results.set(artifact_hash, { artifact_hash, canonical_json, artifact });
  }

  /**
   * @param {string} artifact_hash
   */
  getReplayResult(artifact_hash) {
    return this.replay_results.get(artifact_hash);
  }
}
