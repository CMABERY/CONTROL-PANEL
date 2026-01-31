#!/usr/bin/env node
/**
 * Fixture Validation CLI
 * 
 * Quick pass/fail check for all fixtures without the full test runner.
 * Run with: npm run validate
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

// Load schema
const schema = JSON.parse(readFileSync(join(ROOT, 'bundle.schema.json'), 'utf8'));

// Initialize validator
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(schema);

// Create validators
const validators = {
  index: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Index' }),
  checkpoint: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Checkpoint' }),
  reconcile_session: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ReconcileSession' }),
  reflog_entry: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ReflogEntry' }),
  validation_result: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ValidationResult' }),
  validation_issue: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/ValidationIssue' }),
  conflict: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/Conflict' }),
  patch_op: ajv.compile({ $ref: 'https://flowversion.dev/schemas/bundle.json#/$defs/PatchOp' }),
};

let passed = 0;
let failed = 0;

function checkFixtures(baseDir, expectValid) {
  if (!existsSync(baseDir)) {
    console.log(`  (no fixtures in ${baseDir})`);
    return;
  }
  
  const typeDirs = readdirSync(baseDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);
  
  for (const typeDir of typeDirs) {
    const validator = validators[typeDir];
    if (!validator) {
      continue;
    }
    
    const typePath = join(baseDir, typeDir);
    const files = readdirSync(typePath).filter(f => f.endsWith('.json'));
    
    for (const file of files) {
      const filePath = join(typePath, file);
      const content = JSON.parse(readFileSync(filePath, 'utf8'));
      
      // Remove test metadata
      const data = { ...content };
      delete data._comment;
      delete data._expected_error;
      
      const valid = validator(data);
      const expectedOutcome = expectValid ? 'valid' : 'invalid';
      const actualOutcome = valid ? 'valid' : 'invalid';
      
      if ((expectValid && valid) || (!expectValid && !valid)) {
        console.log(`  ✓ ${typeDir}/${file}`);
        passed++;
      } else {
        console.log(`  ✗ ${typeDir}/${file} (expected ${expectedOutcome}, got ${actualOutcome})`);
        if (validator.errors) {
          console.log(`    Errors: ${JSON.stringify(validator.errors)}`);
        }
        failed++;
      }
    }
  }
}

console.log('\nValidating fixtures...\n');

console.log('Valid fixtures (should pass):');
checkFixtures(join(ROOT, 'fixtures', 'valid'), true);

console.log('\nInvalid fixtures (should fail):');
checkFixtures(join(ROOT, 'fixtures', 'invalid'), false);

console.log(`\n${'='.repeat(40)}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`${'='.repeat(40)}\n`);

process.exit(failed > 0 ? 1 : 0);
