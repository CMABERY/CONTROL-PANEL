/**
 * flowversion-conformance
 * 
 * Conformance harness for Domain-Native Version Control Kit adapters.
 * 
 * This package provides:
 * - JSON Schema for kernel objects (Index, Checkpoint, ReconcileSession, etc.)
 * - Reference canonicalizer implementation
 * - Test fixtures (valid and invalid)
 * - Test runners for conformance checking
 */

// Schema + contract version (bump on breaking changes to bundle.schema.json or adapter contract)
export const SPEC_VERSION = "0.1.0";

// Canonicalization rules version (bump on any change that could alter canonical bytes / hashes)
export const CANON_VERSION = "0.1.0";


export { 
  canonicalize, 
  serialize, 
  deserialize, 
  canonicalEqual,
  hashCanonical,
  hashValueOrAbsent,
  ABSENT 
} from './canonicalize.js';

// Re-export schema loading utility
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export function loadSchema() {
  return JSON.parse(readFileSync(join(__dirname, '..', 'bundle.schema.json'), 'utf8'));
}
