import { readFileSync, writeFileSync } from 'node:fs';
import { canonicalize, serialize, hashCanonical } from '../src/canonicalize.js';
import { SPEC_VERSION, CANON_VERSION } from '../src/index.js';

const sourcePath = new URL('./goldens.source.json', import.meta.url);
const outPath = new URL('../goldens.json', import.meta.url);

const { version, vectors } = JSON.parse(readFileSync(sourcePath, 'utf8'));

const out = [];
for (const vec of vectors) {
  const canonical = canonicalize(vec.input);
  const bytes = serialize(canonical);
  const canonical_json = new TextDecoder().decode(bytes);
  const sha256 = await hashCanonical(vec.input);

  out.push({
    name: vec.name,
    notes: vec.notes,
    input: vec.input,
    canonical_json,
    sha256
  });
}

const _meta = {
  spec_version: SPEC_VERSION,
  canon_version: CANON_VERSION,
  generated_at: new Date().toISOString(),
  generator: 'flowversion-conformance'
};

writeFileSync(outPath, JSON.stringify({ _meta, version, vectors: out }, null, 2) + '\n', 'utf8');
process.stdout.write(`Wrote ${out.length} golden vectors to ${outPath.pathname}\n`);
