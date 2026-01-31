/**
 * Canonicalization Conformance Tests
 * 
 * Tests for the determinism invariants that all adapters MUST uphold.
 * Run with: node --test src/canonicalization.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { 
  canonicalize, 
  serialize, 
  deserialize, 
  canonicalEqual,
  hashCanonical,
  hashValueOrAbsent,
  ABSENT 
} from './canonicalize.js';
import { SPEC_VERSION, CANON_VERSION } from './index.js';

describe('Canonicalization - Idempotence (Invariant 1)', () => {
  test('canonicalize(canonicalize(S)) === canonicalize(S)', () => {
    const testCases = [
      { a: 1, b: 'hello', c: [1, 2, 3] },
      { z: 1, a: 2, m: 3 }, // unordered keys
      { nested: { deep: { value: true } } },
      [1, 'two', { three: 3 }],
      null,
      42,
      'string',
      true,
    ];
    
    for (const input of testCases) {
      const once = canonicalize(input);
      const twice = canonicalize(once);
      assert.deepEqual(once, twice, `Idempotence failed for: ${JSON.stringify(input)}`);
    }
  });
  
  test('Key ordering is lexicographic', () => {
    const input = { zebra: 1, apple: 2, mango: 3, Banana: 4 };
    const canon = canonicalize(input);
    const keys = Object.keys(canon);
    
    // 'B' < 'a' in Unicode code point order
    assert.deepEqual(keys, ['Banana', 'apple', 'mango', 'zebra']);
  });
});

describe('Serialization - Determinism (Invariant 2)', () => {
  test('serialize(canonicalize(S)) is stable', () => {
    const input = { b: 2, a: 1, c: { z: 26, a: 1 } };
    
    // Serialize multiple times
    const bytes1 = serialize(canonicalize(input));
    const bytes2 = serialize(canonicalize(input));
    const bytes3 = serialize(canonicalize(input));
    
    // All should be identical
    assert.deepEqual(bytes1, bytes2);
    assert.deepEqual(bytes2, bytes3);
    
    // Verify actual byte content
    const decoded = new TextDecoder().decode(bytes1);
    assert.equal(decoded, '{"a":1,"b":2,"c":{"a":1,"z":26}}');
  });
  
  test('Safe integers serialize deterministically', () => {
  const testCases = [
    [0, '0'],
    [1, '1'],
    [-1, '-1'],
    [42, '42'],
    [Number.MAX_SAFE_INTEGER, String(Number.MAX_SAFE_INTEGER)],
    [-Number.MAX_SAFE_INTEGER, String(-Number.MAX_SAFE_INTEGER)],
    [1e10, '10000000000'], // still a safe integer
  ];

  for (const [input, expected] of testCases) {
    const bytes = serialize(canonicalize(input));
    const decoded = new TextDecoder().decode(bytes);
    assert.equal(decoded, expected, `Integer serialization failed for ${input}`);
  }
});

test('Non-integer numbers throw', () => {
  const bad = [0.5, -0.1, 1e-7, 1.23456789];
  for (const input of bad) {
    assert.throws(() => canonicalize(input), /Non-integer numbers are not allowed/);
  }
});

test('Unsafe integers throw', () => {
  const bad = [Number.MAX_SAFE_INTEGER + 1, 9007199254740992];
  for (const input of bad) {
    assert.throws(() => canonicalize(input), /Unsafe integer/);
  }
});
});

describe('Round-trip - Determinism (Invariant 3)', () => {
  test('canonicalize(deserialize(serialize(canonicalize(S)))) === canonicalize(S)', () => {
    const testCases = [
      { a: 1, b: 'hello', c: [1, 2, 3] },
      { nested: { deep: { array: [{ x: 1 }] } } },
      [1, 2, 3, { key: 'value' }],
      'simple string',
      12345,
      true,
      null,
    ];
    
    for (const input of testCases) {
      const canonical = canonicalize(input);
      const bytes = serialize(canonical);
      const deserialized = deserialize(bytes);
      
      assert.deepEqual(canonical, deserialized, 
        `Round-trip failed for: ${JSON.stringify(input)}`);
    }
  });
});

describe('String Normalization', () => {
  test('UUIDs are normalized to lowercase', () => {
    const upper = 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890';
    const canon = canonicalize(upper);
    assert.equal(canon, 'a1b2c3d4-e5f6-7890-abcd-ef1234567890');
  });
  
  test('Hashes are normalized to lowercase', () => {
    const upper = 'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890';
    const canon = canonicalize(upper);
    assert.equal(canon, 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890');
  });
  
  test('Timestamps are normalized to UTC', () => {
    const inputs = [
      '2024-01-15T10:00:00-08:00',
      '2024-01-15T18:00:00+00:00',
      '2024-01-15T18:00:00Z',
    ];
    
    // All should normalize to the same value (sans milliseconds variation)
    const results = inputs.map(i => canonicalize(i));
    assert.equal(results[0], '2024-01-15T18:00:00Z');
    assert.equal(results[1], '2024-01-15T18:00:00Z');
    assert.equal(results[2], '2024-01-15T18:00:00Z');
  });
  
  test('Timestamps preserve milliseconds when non-zero', () => {
    const withMs = '2024-01-15T18:00:00.123Z';
    const canon = canonicalize(withMs);
    assert.equal(canon, '2024-01-15T18:00:00.123Z');
  });
});

describe('canonicalEqual', () => {
  test('Detects equivalent objects with different key order', () => {
    const a = { z: 1, a: 2 };
    const b = { a: 2, z: 1 };
    assert.ok(canonicalEqual(a, b));
  });
  
  test('Detects non-equivalent objects', () => {
    const a = { x: 1 };
    const b = { x: 2 };
    assert.ok(!canonicalEqual(a, b));
  });
  
  test('Handles nested structures', () => {
    const a = { outer: { inner: [1, 2] } };
    const b = { outer: { inner: [1, 2] } };
    const c = { outer: { inner: [1, 3] } };
    
    assert.ok(canonicalEqual(a, b));
    assert.ok(!canonicalEqual(a, c));
  });
});

describe('Hashing', () => {
  test('hashCanonical produces consistent hashes', async () => {
    const input = { a: 1, b: 2 };
    
    const hash1 = await hashCanonical(input);
    const hash2 = await hashCanonical(input);
    const hash3 = await hashCanonical({ b: 2, a: 1 }); // Same data, different key order
    
    assert.equal(hash1, hash2);
    assert.equal(hash1, hash3);
    assert.match(hash1, /^[a-f0-9]{64}$/);
  });
  
  test('Different values produce different hashes', async () => {
    const hash1 = await hashCanonical({ a: 1 });
    const hash2 = await hashCanonical({ a: 2 });
    
    assert.notEqual(hash1, hash2);
  });
  
  test('hashValueOrAbsent distinguishes null from absent', async () => {
    const hashNull = await hashValueOrAbsent(null);
    const hashAbsent = await hashValueOrAbsent(ABSENT);
    
    assert.notEqual(hashNull, hashAbsent, 
      'null and ABSENT must produce different hashes');
  });
});

describe('Edge Cases', () => {
  test('Undefined throws error', () => {
    assert.throws(() => canonicalize(undefined), /Undefined is not valid/);
  });
  
  test('NaN throws error', () => {
    assert.throws(() => canonicalize(NaN), /Non-finite numbers not allowed/);
  });
  
  test('Infinity throws error', () => {
    assert.throws(() => canonicalize(Infinity), /Non-finite numbers not allowed/);
  });
  
  test('Empty objects and arrays', () => {
    assert.deepEqual(canonicalize({}), {});
    assert.deepEqual(canonicalize([]), []);
  });
  
  test('Deeply nested structures', () => {
    const deep = { a: { b: { c: { d: { e: { f: 'deep' } } } } } };
    const canon = canonicalize(deep);
    assert.equal(canon.a.b.c.d.e.f, 'deep');
  });
});

describe('Golden Vectors (Normative)', () => {
  // These vectors are normative: implementations MUST produce identical
  // canonical JSON bytes and SHA-256 hashes for the given inputs.
  const goldensPath = new URL('../goldens.json', import.meta.url);
  const { version, vectors, _meta } = JSON.parse(readFileSync(goldensPath, 'utf8'));

    test('Goldens file embeds spec/canon versions', () => {
    assert.ok(_meta && typeof _meta === 'object');
    assert.equal(_meta.spec_version, SPEC_VERSION);
    assert.equal(_meta.canon_version, CANON_VERSION);
    assert.equal(_meta.generator, 'flowversion-conformance');
    assert.ok(typeof _meta.generated_at === 'string');
  });

test('Goldens file has expected shape', () => {
    assert.equal(version, 1);
    assert.ok(Array.isArray(vectors));
    assert.ok(vectors.length >= 10);
  });

  for (const vec of vectors) {
    test(`Golden: ${vec.name}`, async () => {
      const canonical = canonicalize(vec.input);
      const bytes = serialize(canonical);
      const json = new TextDecoder().decode(bytes);
      const hash = await hashCanonical(vec.input);

      assert.equal(json, vec.canonical_json, `Canonical JSON mismatch for ${vec.name}`);
      assert.equal(hash, vec.sha256, `Hash mismatch for ${vec.name}`);
      assert.match(hash, /^[a-f0-9]{64}$/);
    });
  }

  test('ABSENT hashes to the absent sentinel golden vector', async () => {
    const absentVec = vectors.find(v => v.name === 'absent_sentinel_object');
    assert.ok(absentVec, 'Missing absent_sentinel_object vector in goldens.json');

    const hashAbsent = await hashValueOrAbsent(ABSENT);
    assert.equal(hashAbsent, absentVec.sha256);
  });
});

