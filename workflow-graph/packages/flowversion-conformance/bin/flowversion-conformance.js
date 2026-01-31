#!/usr/bin/env node
/**
 * flowversion-conformance CLI
 *
 * Minimal, dependency-free wrapper around the harness.
 *
 * Commands:
 *   flowversion-conformance test [--config <path>]
 *   flowversion-conformance validate
 *   flowversion-conformance gen-goldens
 *   flowversion-conformance gen-domain-goldens [--config <path>]
 */

import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SPEC_VERSION, CANON_VERSION } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

function printBanner() {
  // Always print a version banner for log-greppable CI diagnostics.
  process.stdout.write(`flowversion-conformance spec=${SPEC_VERSION} canon=${CANON_VERSION} node=${process.version}\n`);
}


function usage(code = 0) {
  const msg = `flowversion-conformance

Usage:
  flowversion-conformance test [--config <path>]
  flowversion-conformance validate
  flowversion-conformance gen-goldens
  flowversion-conformance gen-domain-goldens [--config <path>]

Notes:
  - Adapter certification is enabled automatically when a conformance.config.json
    is found in the current working directory (or when --config is provided).
  - The CLI runs harness code from its install location, but keeps process.cwd()
    as your repo root so config/fixtures resolve correctly.
`;

  process.stdout.write(msg);
  process.exit(code);
}

function parseArgs(argv) {
  const args = {
    cmd: null,
    config: null,
    rest: [],
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    if (!args.cmd && !a.startsWith('-')) {
      args.cmd = a;
      continue;
    }

    if (a === '--help' || a === '-h' || a === 'help') {
      usage(0);
    }

    if (a === '--config') {
      const v = argv[i + 1];
      if (!v) {
        process.stderr.write('Error: --config requires a path\n');
        usage(2);
      }
      args.config = v;
      i++;
      continue;
    }

    args.rest.push(a);
  }

  return args;
}

function runNode(nodeArgs, { env } = {}) {
  const result = spawnSync(process.execPath, nodeArgs, {
    cwd: process.cwd(),
    env: env ?? process.env,
    stdio: 'inherit',
  });

  if (result.error) {
    process.stderr.write(`Error: ${result.error.message}\n`);
    process.exit(1);
  }

  process.exit(result.status ?? 0);
}

function listTestFiles() {
  const srcDir = join(ROOT, 'src');
  const files = readdirSync(srcDir)
    .filter((f) => f.endsWith('.test.js'))
    .map((f) => join(srcDir, f));

  // Ensure a deterministic order (useful for debugging)
  files.sort();
  return files;
}

const { cmd, config } = parseArgs(process.argv.slice(2));

if (!cmd) usage(2);

printBanner();


// If a config is provided, propagate it the same way the harness expects.
const env = { ...process.env };
if (config) env.CONFORMANCE_CONFIG = config;

switch (cmd) {
  case 'test': {
    const tests = listTestFiles();
    runNode(['--test', ...tests], { env });
    break;
  }

  case 'validate': {
    runNode([join(ROOT, 'src', 'validate-fixtures.js')], { env });
    break;
  }

  case 'gen-goldens': {
    runNode([join(ROOT, 'scripts', 'generate-goldens.mjs')], { env });
    break;
  }

  case 'gen-domain-goldens': {
    runNode([join(ROOT, 'scripts', 'generate-domain-goldens.mjs')], { env });
    break;
  }

  default:
    process.stderr.write(`Error: unknown command "${cmd}"\n\n`);
    usage(2);
}
