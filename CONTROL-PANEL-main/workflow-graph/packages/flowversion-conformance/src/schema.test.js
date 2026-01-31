/**
 * Schema Conformance Tests
 * 
 * Tests that the JSON Schema correctly validates/rejects fixtures.
 * Run with: node --test src/schema.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

// Load schema bundle
const schema = JSON.parse(readFileSync(join(ROOT, 'bundle.schema.json'), 'utf8'));

// Initialize validator
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(schema);

// Create validators for each type
const validators = {
  Index: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Index' }),
  Checkpoint: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Checkpoint' }),
  ReconcileSession: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ReconcileSession' }),
  ReflogEntry: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ReflogEntry' }),
  ValidationResult: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ValidationResult' }),
  ValidationIssue: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ValidationIssue' }),
  Conflict: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Conflict' }),
  PatchOp: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/PatchOp' }),
  StagedEntry: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/StagedEntry' }),
};

// Map directory names to validator keys
const dirToType = {
  'index': 'Index',
  'checkpoint': 'Checkpoint',
  'reconcile_session': 'ReconcileSession',
  'reflog_entry': 'ReflogEntry',
  'validation_result': 'ValidationResult',
  'validation_issue': 'ValidationIssue',
  'conflict': 'Conflict',
  'patch_op': 'PatchOp',
};

/**
 * Load all fixtures from a directory
 */
function loadFixtures(baseDir) {
  const fixtures = [];
  
  if (!existsSync(baseDir)) {
    return fixtures;
  }
  
  const typeDirs = readdirSync(baseDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);
  
  for (const typeDir of typeDirs) {
    const typePath = join(baseDir, typeDir);
    const files = readdirSync(typePath)
      .filter(f => f.endsWith('.json'));
    
    for (const file of files) {
      const filePath = join(typePath, file);
      const content = JSON.parse(readFileSync(filePath, 'utf8'));
      fixtures.push({
        type: dirToType[typeDir] || typeDir,
        name: file.replace('.json', ''),
        path: filePath,
        content,
        expectedError: content._expected_error,
      });
    }
  }
  
  return fixtures;
}

// Load fixtures
const validFixtures = loadFixtures(join(ROOT, 'fixtures', 'valid'));
const invalidFixtures = loadFixtures(join(ROOT, 'fixtures', 'invalid'));

describe('Schema Validation - Valid Fixtures', () => {
  for (const fixture of validFixtures) {
    test(`${fixture.type}/${fixture.name} should be valid`, () => {
      const validator = validators[fixture.type];
      if (!validator) {
        // Skip types without explicit validators (nested types)
        return;
      }
      
      // Remove test metadata before validation
      const data = { ...fixture.content };
      delete data._comment;
      delete data._expected_error;
      
      const valid = validator(data);
      if (!valid) {
        const errors = validator.errors
          .map(e => `${e.instancePath} ${e.message}`)
          .join('; ');
        assert.fail(`Expected valid but got errors: ${errors}`);
      }
    });
  }
});

describe('Schema Validation - Invalid Fixtures', () => {
  for (const fixture of invalidFixtures) {
    test(`${fixture.type}/${fixture.name} should be invalid`, () => {
      const validator = validators[fixture.type];
      if (!validator) {
        // Skip types without explicit validators
        return;
      }
      
      // Remove test metadata before validation
      const data = { ...fixture.content };
      delete data._comment;
      delete data._expected_error;
      
      const valid = validator(data);
      assert.equal(valid, false, `Expected invalid but validation passed`);
      
      // If expected error pattern specified, check it
      if (fixture.expectedError) {
        const errorText = JSON.stringify(validator.errors);
        assert.ok(
          errorText.includes(fixture.expectedError),
          `Expected error containing "${fixture.expectedError}" but got: ${errorText}`
        );
      }
    });
  }
});

describe('Schema Definitions', () => {
  test('All $defs are present', () => {
    const expectedDefs = [
      'CheckpointId', 'AtomId', 'AtomSelector', 'Timestamp', 'Hash256', 'UUID',
      'Author', 'PatchOp', 'StagedEntry', 'Index', 'TreeRef', 'Checkpoint',
      'ConflictSeverity', 'ResolutionAction', 'Conflict', 'Resolution',
      'ReconcileSessionStatus', 'ReconcileSession', 'ReflogAction', 'ReflogEntry',
      'ValidationSeverity', 'ValidationIssue', 'ValidationResult'
    ];
    
    for (const def of expectedDefs) {
      assert.ok(schema.$defs[def], `Missing $def: ${def}`);
    }
  });
  
  test('Hash256 pattern matches valid hashes', () => {
    const validator = ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Hash256' });
    
    // Valid hashes
    assert.ok(validator('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'));
    assert.ok(validator('0000000000000000000000000000000000000000000000000000000000000000'));
    
    // Invalid hashes
    assert.ok(!validator('ABCDEF')); // uppercase
    assert.ok(!validator('abcdef')); // too short
    assert.ok(!validator('xyz')); // not hex
  });
  
  test('AtomSelector pattern matches valid selectors', () => {
    const validator = ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/AtomSelector' });
    
    // Valid selectors
    assert.ok(validator('node:abc123'));
    assert.ok(validator('edge:a->b'));
    assert.ok(validator('field:node123./config/timeout'));
    assert.ok(validator('region:area-1'));
    assert.ok(validator('path:/workflows/main.json'));
    assert.ok(validator('blob:sha256:abcd'));
    
    // Invalid selectors
    assert.ok(!validator('abc123')); // missing type prefix
    assert.ok(!validator('node:')); // missing id
    assert.ok(!validator('invalid:abc')); // wrong prefix
  });
});
