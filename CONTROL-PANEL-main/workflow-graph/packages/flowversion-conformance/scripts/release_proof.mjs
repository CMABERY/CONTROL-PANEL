#!/usr/bin/env node
import fs from "node:fs";

function die(msg) {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
}

function readJSON(path) {
  if (!fs.existsSync(path)) return null;
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (e) {
    die(`failed to parse JSON at ${path}: ${e.message}`);
  }
}

function writeJSON(path, obj) {
  fs.writeFileSync(path, JSON.stringify(obj, null, 2) + "\n");
}

function arg(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return null;
  const v = process.argv[i + 1];
  if (!v || v.startsWith("--")) return null;
  return v;
}

const cmd = process.argv[2];
if (!cmd || !["init", "verify"].includes(cmd)) {
  die("usage: release_proof.mjs <init|verify> --file ... (see script)");
}

const file = arg("--file");
const pkg = arg("--package");
const version = arg("--version");
if (!file) die("--file required");
if (!pkg) die("--package required");
if (!version) die("--version required");

let doc = readJSON(file);
if (!doc) {
  doc = {
    schema_version: 1,
    package: pkg,
    releases: {}
  };
}

if (doc.package !== pkg) {
  die(`RELEASE_PROOF.json package mismatch: expected '${pkg}', found '${doc.package}'`);
}

if (cmd === "init") {
  const commit = arg("--commit");
  const tarball = arg("--tarball");
  const sha256 = arg("--sha256");
  const timestamp = arg("--timestamp");
  const distTag = arg("--dist-tag");

  if (!commit || !tarball || !sha256 || !timestamp || !distTag) {
    die("init requires --commit --tarball --sha256 --timestamp --dist-tag");
  }

  if (doc.releases[version]) {
    // Hard fail to prevent accidental overwrite (entry drift).
    die(`release entry already exists for version ${version}`);
  }

  doc.releases[version] = {
    version,
    provenance: {
      commit,
      tarball,
      sha256,
      timestamp_utc: timestamp,
      dist_tag: distTag
    },
    post_publish_verify: null
  };

  writeJSON(file, doc);
  console.log(`OK: initialized release entry for ${version}`);
  process.exit(0);
}

if (cmd === "verify") {
  const timestamp = arg("--timestamp");
  const command = arg("--command");
  const result = arg("--result");

  if (!timestamp || !command || !result) {
    die("verify requires --timestamp --command --result");
  }

  const entry = doc.releases[version];
  if (!entry) die(`no release entry for version ${version} (init must run first)`);

  // Guardrail: assert entry version matches requested version (blocks entry drift).
  if (entry.version !== version) {
    die(`entry drift: releases['${version}'].version != '${version}'`);
  }

  entry.post_publish_verify = {
    timestamp_utc: timestamp,
    command,
    result
  };

  writeJSON(file, doc);
  console.log(`OK: recorded verification for ${version}`);
  process.exit(0);
}
