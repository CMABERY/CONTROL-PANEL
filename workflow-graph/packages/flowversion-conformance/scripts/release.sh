#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# FlowVersion Release Script — Locked Execution Sequence
#
# Implements the 15-step release runbook with hard gates:
#   1. Fix placeholder repo metadata
#   2. Assert metadata is not placeholder (machine check, fail if invalid)
#   3. npm ci && npm test && npm run validate
#   4. npm pack
#   5. Assert tarball is clean (fail on junk/omissions)
#   6. Tarball smoke test (fresh temp dir, npm i /path/to.tgz, run CLI)
#   7. Record provenance (RELEASE.md + RELEASE_PROOF.json with version key)
#   8. Commit provenance
#   9. npm publish
#  10. Tag provenance commit: flowversion-conformance@X.Y.Z+published
#  11. Post-publish verification (npx flowversion-conformance@X.Y.Z test)
#  12. Update RELEASE_PROOF.json (same entry, assert version matches)
#  13. Commit verification evidence
#  14. Tag evidence commit: flowversion-conformance@X.Y.Z
#  15. Push both tags
#
# Tag semantics:
#   @X.Y.Z+published → immutable pointer to pre-publish provenance
#   @X.Y.Z           → verified installable release
#
# Config (env):
#   ALLOW_PUBLISH    Set to 1 to actually publish (default: 0)
#   PUSH_TAGS        Set to 0 to skip pushing tags (default: 1)
#   NPM_DIST_TAG     npm dist-tag (default: latest)
#   NPM_ACCESS       npm access level (default: public)
# ==============================================================================

die() { echo "RELEASE FAIL: $*" >&2; exit 1; }
info() { echo "==> $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
need_cmd node
need_cmd npm
need_cmd git
need_cmd tar

# Config defaults
PACKAGE_JSON="${PACKAGE_JSON:-package.json}"
RELEASE_MD="${RELEASE_MD:-RELEASE.md}"
RELEASE_PROOF_JSON="${RELEASE_PROOF_JSON:-RELEASE_PROOF.json}"
NPM_DIST_TAG="${NPM_DIST_TAG:-latest}"
NPM_ACCESS="${NPM_ACCESS:-public}"
ALLOW_PUBLISH="${ALLOW_PUBLISH:-0}"
PUSH_TAGS="${PUSH_TAGS:-1}"

# Forbidden patterns in tarball
FORBIDDEN_TARBALL_REGEX=(
  '^package/node_modules/'
  '^package/\.git/'
  '^package/\.env$'
  '^package/\.DS_Store$'
  '^package/\.vscode/'
  '^package/\.idea/'
  '^package/npm-debug\.log$'
  '^package/yarn-error\.log$'
  '^package/\.npmrc$'
)

# Read package info
PKG_NAME="$(node -p "require('./${PACKAGE_JSON}').name")"
PKG_VERSION="$(node -p "require('./${PACKAGE_JSON}').version")"
BIN_NAME="$(node -e "const p=require('./${PACKAGE_JSON}'); if(typeof p.bin==='string'){console.log(p.name)}else if(p.bin){console.log(Object.keys(p.bin)[0])}else{process.exit(1)}")"

PUBLISHED_TAG="${PKG_NAME}@${PKG_VERSION}+published"
VERIFIED_TAG="${PKG_NAME}@${PKG_VERSION}"

info "Package: ${PKG_NAME}"
info "Version: ${PKG_VERSION}"
info "Bin: ${BIN_NAME}"
info "Tags: ${PUBLISHED_TAG} | ${VERIFIED_TAG}"

# ==============================================================================
# Step 1-2: Metadata validity
# ==============================================================================
info "Checking repository metadata is present and non-placeholder..."
node -e "
const p=require('./${PACKAGE_JSON}');
const repo = p.repository;
const repoStr = repo ? JSON.stringify(repo) : '';
const hasGitHub = repoStr.includes('github.com/');
const hasPlaceholder = /placeholder|example|tbd/i.test(repoStr);

if (!repo) { console.error('repository field missing'); process.exit(1); }
if (!hasGitHub) { console.error('repository field does not look like a GitHub URL'); process.exit(1); }
if (hasPlaceholder) { console.error('repository field still looks placeholder-ish'); process.exit(1); }
console.log('repository metadata OK');
"

# ==============================================================================
# Step 3: Tests/validation
# ==============================================================================
info "Running npm ci..."
npm ci

info "Running npm test..."
npm test

info "Running npm run validate..."
npm run validate

# ==============================================================================
# Step 4: Pack
# ==============================================================================
info "Packing tarball (npm pack)..."
TGZ="$(npm pack 2>/dev/null)"
[[ -f "$TGZ" ]] || die "expected tarball not found: $TGZ"
TGZ_ABS="$(cd "$(dirname "$TGZ")" && pwd)/$(basename "$TGZ")"
info "Created tarball: $TGZ_ABS"

# ==============================================================================
# Step 5: Tarball cleanliness gate
# ==============================================================================
info "Inspecting tarball contents..."
TAR_LIST="$(tar -tf "$TGZ_ABS")"

echo "$TAR_LIST" | grep -qx 'package/package.json' || die "tarball missing package/package.json"

for rx in "${FORBIDDEN_TARBALL_REGEX[@]}"; do
  if echo "$TAR_LIST" | grep -Eq "$rx"; then
    die "tarball contains forbidden path matching: $rx"
  fi
done
info "Tarball content gate passed."

# ==============================================================================
# Step 6: Smoke test from tarball
# ==============================================================================
info "Smoke testing tarball install in a fresh temp dir..."
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

pushd "$TMPDIR" >/dev/null
npm init -y >/dev/null 2>&1
npm i "$TGZ_ABS" >/dev/null

BIN_PATH="./node_modules/.bin/${BIN_NAME}"
[[ -x "$BIN_PATH" ]] || die "expected installed bin not found/executable: $BIN_PATH"

"$BIN_PATH" --version >/dev/null 2>&1 || die "smoke: '${BIN_NAME} --version' failed"
"$BIN_PATH" test || die "smoke: '${BIN_NAME} test' failed"
popd >/dev/null
info "Tarball smoke test passed."

# ==============================================================================
# Step 7-8: Record provenance and commit
# ==============================================================================
info "Recording provenance..."
SHA256="$(shasum -a 256 "$TGZ_ABS" | awk '{print $1}')"
COMMIT="$(git rev-parse HEAD)"
UTC_NOW="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat >> "$RELEASE_MD" <<EOF

## ${PKG_NAME} ${PKG_VERSION}
- timestamp_utc: ${UTC_NOW}
- commit: ${COMMIT}
- tarball: $(basename "$TGZ_ABS")
- sha256: ${SHA256}
- dist_tag: ${NPM_DIST_TAG}
EOF

node scripts/release_proof.mjs init \
  --file "$RELEASE_PROOF_JSON" \
  --package "$PKG_NAME" \
  --version "$PKG_VERSION" \
  --commit "$COMMIT" \
  --tarball "$(basename "$TGZ_ABS")" \
  --sha256 "$SHA256" \
  --timestamp "$UTC_NOW" \
  --dist-tag "$NPM_DIST_TAG"

git add "$RELEASE_MD" "$RELEASE_PROOF_JSON"
git commit -m "release: ${PKG_NAME} ${PKG_VERSION} provenance"
PROVENANCE_COMMIT="$(git rev-parse HEAD)"

# ==============================================================================
# Step 9: Publish
# ==============================================================================
if [[ "$ALLOW_PUBLISH" != "1" ]]; then
  die "Refusing to publish: set ALLOW_PUBLISH=1 to proceed (guardrail)"
fi

info "Checking npm auth..."
npm whoami >/dev/null 2>&1 || die "not logged into npm (npm whoami failed)"

info "Publishing to npm..."
npm publish --access "$NPM_ACCESS" --tag "$NPM_DIST_TAG"

# ==============================================================================
# Step 10: Tag published-provenance commit
# ==============================================================================
info "Tagging published provenance commit: ${PUBLISHED_TAG}"
git tag -a "$PUBLISHED_TAG" -m "${PKG_NAME} ${PKG_VERSION} published (provenance)" "$PROVENANCE_COMMIT"

# ==============================================================================
# Step 11: Post-publish verification
# ==============================================================================
info "Post-publish verification via npx..."
VERIFY_TMP="$(mktemp -d)"
trap 'rm -rf "$TMPDIR" "$VERIFY_TMP"' EXIT

pushd "$VERIFY_TMP" >/dev/null
npm init -y >/dev/null 2>&1

VERIFY_CMD="npx --yes -p ${PKG_NAME}@${PKG_VERSION} ${BIN_NAME} test"
set +e
VERIFY_OUT="$($VERIFY_CMD 2>&1)"
VERIFY_CODE=$?
set -e
popd >/dev/null

[[ $VERIFY_CODE -eq 0 ]] || {
  echo "$VERIFY_OUT" >&2
  die "post-publish verification failed (exit $VERIFY_CODE)"
}
info "Post-publish verification passed."

# ==============================================================================
# Step 12-13: Update proof with verification evidence and commit
# ==============================================================================
info "Updating RELEASE_PROOF.json with verification evidence..."
UTC_NOW2="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

node scripts/release_proof.mjs verify \
  --file "$RELEASE_PROOF_JSON" \
  --package "$PKG_NAME" \
  --version "$PKG_VERSION" \
  --timestamp "$UTC_NOW2" \
  --command "$VERIFY_CMD" \
  --result "pass"

git add "$RELEASE_PROOF_JSON"
git commit -m "release: ${PKG_NAME} ${PKG_VERSION} verification evidence"
EVIDENCE_COMMIT="$(git rev-parse HEAD)"

# ==============================================================================
# Step 14: Tag verified-evidence commit
# ==============================================================================
info "Tagging verified evidence commit: ${VERIFIED_TAG}"
git tag -a "$VERIFIED_TAG" -m "${PKG_NAME} ${PKG_VERSION} verified" "$EVIDENCE_COMMIT"

# ==============================================================================
# Step 15: Push tags
# ==============================================================================
if [[ "$PUSH_TAGS" == "1" ]]; then
  info "Pushing tags..."
  git push --tags
else
  info "Skipping tag push (PUSH_TAGS=0)."
fi

info "Done. Published + tagged with explicit semantics."
