# CONTROL-PANEL: Tamper-Evident Evidence for AI-Assisted Decisions

## What this is

This repository demonstrates how AI-assisted actions can be recorded as cryptographically verifiable decision records.
The goal is not control or enforcement — only **audit-grade evidence** of what happened.

## What it proves

* AI actions can be logged without modifying the model
* Decision records are hashed and signed
* Evidence can be independently verified
* Records are exportable for audit/compliance review

## What it is not

* Not a policy engine
* Not an AI safety framework
* Not production software

---

## Run the Evidence Flow (2 minutes)

This is the single **blessed path** through the repo: take a decision record, hash it deterministically, sign it, and verify it **without reading any code**.

**Prerequisites:** `python3`, `openssl`

### 1) Prepare the input (stable, intentional)

```bash
mkdir -p evidence_pack
cp workflow-graph/packages/keystone-gate-runtime/goldens/integration.e2e.goldens.json evidence_pack/source_vector.json
```

### 2) Run command (decision happens, record emitted)

```bash
python3 - <<'PY'
import json, hashlib, pathlib

src = pathlib.Path('evidence_pack/source_vector.json')
data = json.loads(src.read_text(encoding='utf-8'))

vec = next(v for v in data['vectors'] if v['name'] == 'e2e_allow_model_call_ok')
step = next(s for s in vec['steps'] if s['record_type'] == 'policy_decision')

record = step['input']
canonical_json = step['canonical_json']
expected_sha256 = step['sha256']

computed_sha256 = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
assert computed_sha256 == expected_sha256, (computed_sha256, expected_sha256)

out_dir = pathlib.Path('evidence_pack')
(out_dir / 'decision_record.json').write_text(canonical_json + '\n', encoding='utf-8')
(out_dir / 'decision_record.sha256').write_text(computed_sha256 + '\n', encoding='utf-8')

print('Decision result:', record['decision']['result'])
print('Record emitted:', out_dir / 'decision_record.json')
print('SHA-256:', computed_sha256)
PY
```

You should see output similar to:

```
Decision result: allow
Record emitted: evidence_pack/decision_record.json
SHA-256: <hash>
```

### 3) Hash + sign output

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out evidence_pack/signing_key_rsa.pem
openssl pkey -in evidence_pack/signing_key_rsa.pem -pubout -out evidence_pack/signing_key_rsa.pub.pem

openssl dgst -sha256 \
  -sign evidence_pack/signing_key_rsa.pem \
  -out evidence_pack/decision_record.sig \
  evidence_pack/decision_record.json
```

### 4) Verify (independent)

```bash
openssl dgst -sha256 \
  -verify evidence_pack/signing_key_rsa.pub.pem \
  -signature evidence_pack/decision_record.sig \
  evidence_pack/decision_record.json \
  | tee evidence_pack/verify.out
```

Successful verification prints:

```
Verified OK
```

---

## Evidence Pack

This produces an **Evidence Pack** consisting of:

* Decision record (`evidence_pack/decision_record.json`)
* Cryptographic hash (`evidence_pack/decision_record.sha256`)
* Signature (`evidence_pack/decision_record.sig`)
* Verification output (`evidence_pack/verify.out`)

All artifacts are independently verifiable and exportable.

---

## Deep dive (optional)

### Repository status

**Repository status:** Week 1 demo repo. Scope intentionally limited to evidence flow + verification.

### CPO Governance Kernel (`/cpo`)

A PostgreSQL-native governance kernel where all state mutation flows through a single write aperture (`cpo.commit_action`).
Enforcement is fail-closed by default; invariants are proven via deterministic self-tests.

### FlowVersion Conformance Toolkit

`/workflow-graph/packages/flowversion-conformance`

A domain-native version control system that generalizes Git’s trust properties beyond files, enforcing correctness via canonicalization, schema validation, and golden vectors.

### Keystone Gate Envelope System

`/workflow-graph/packages/keystone-gate-runtime`

Implements canonical decision envelopes with:

* Deterministic JSON canonicalization
* SHA-256 content addressing
* Schema validation (Draft 2020-12)
* Golden vectors for reproducibility
* Replay and verification plumbing

### Integration model

```
[Domain Action]
   → Canonicalize
   → Hash
   → Sign
   → Verify
   → Persist as evidence
```

The system is designed to produce **proof artifacts**, not to enforce policy or constrain behavior.

---

## License

See `LICENSE`.

---
