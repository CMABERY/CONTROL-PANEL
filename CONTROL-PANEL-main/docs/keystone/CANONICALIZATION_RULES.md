# Canonicalization & Hashing Rules (LOCKED)

**Status:** Canonical (SPEC_VERSION 1.0.0, CANON_VERSION 1)

This document defines the *normative* canonicalization and hashing rules for all
Phase 1–6 envelope records and replay/certification artifacts.

## 1) Canonical JSON bytes

Canonical JSON is produced using **RFC 8785 — JSON Canonicalization Scheme (JCS)**.

Normative requirements:

- Input must be valid JSON data (objects/arrays/strings/integers/booleans/null).
- **Object member names are sorted lexicographically by Unicode code points** (as per JCS).
- Strings are encoded using JSON string escaping rules (JCS / RFC 8785).
- Numbers in persisted envelopes MUST be **integers only** and must validate as JSON Schema `type: "integer"`.
  - Floating point numbers are invalid in envelope records and must be rejected by schema validation.
- The canonical JSON output is serialized as UTF-8 bytes with no BOM.

## 2) Hashing

Hashing algorithm: **SHA-256** over canonical JSON UTF-8 bytes.

- Digest encoding: lowercase hex (`[0-9a-f]{64}`).

### 2.1) Envelope hash

`envelope_hash := sha256( utf8( canonical_json( envelope_record ) ) )`

- `envelope_hash` is the **artifact key**.
- `envelope_hash` is computed from the *entire* envelope record (not content-only).

### 2.2) BlobRef content hash

`BlobRef.sha256` is a **content hash** for external payload bytes (request/response blobs).
It is not an artifact key and must not be used as a substitute for `envelope_hash`.

### 2.3) Replay result / certification artifacts

Replay results and certification/revocation records are **not envelope record types**.
They are content-addressed ledger artifacts:

`artifact_sha256 := sha256( utf8( canonical_json( artifact_record ) ) )`

## 3) Determinism & failure posture

- Canonicalization + hashing is deterministic: identical inputs produce identical bytes and hashes.
- Unknown fields fail validation (closed-world).
- Any artifact that cannot be canonicalized/hashed deterministically must FAIL closed.

This document is descriptive of locked behavior. Any change requires a new canon version.
