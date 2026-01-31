# Workflow Graph Adapter (Reference)

This package is the **reference domain walkthrough** for the kit, using a *workflow-builder graph* domain.

It is designed to be:
- small enough to understand in one sitting
- strict enough to be a real certification target

## Run certification

From repo root:

```bash
npm test
```

Or from this package:

```bash
npm test
```

## Files

- `src/workflow-adapter.js` — adapter implementation (canonicalizeDomain/diff/merge/validate)
- `conformance/domain-goldens.json` — normative domain golden vectors
- `conformance/atoms/*` — diff/merge/validate fixtures (with semantic expectations)
- `docs/` — five-questions answers + A-style spec
