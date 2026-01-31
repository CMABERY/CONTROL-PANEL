# Workflow Graph Adapter Spec (B layer, made concrete)

This document explains the adapter implementation in `src/workflow-adapter.js` in contract terms.

## Atom IDs and selectors

- Nodes: `node:<nodeId>`
- Edges: `edge:<edgeId>`
- Workflow root pseudo-atom (for issues that can't point to a specific node): `workflow:root`

These IDs are treated as stable identities (they must not be regenerated on load).

## Canonical domain state

Canonical workflow graph shape:

```json
{
  "kind": "workflow_graph@1",
  "name": "optional",
  "meta": { "...": "..." },
  "nodes": [ { "id": "...", "type": "...", "label": "...", "config": { ... } } ],
  "edges": [ { "id": "...", "from": "...", "to": "...", "type": "flow", "label": "...", "condition": { ... } } ]
}
```

Canonicalization rules:
- Nodes sorted by `id`
- Edges sorted by `id`
- Object keys sorted lexicographically (via the shared base canonicalizer)
- UUID strings, timestamp strings, and 64-hex hashes normalized by the base canonicalizer
- **Numbers are integers only** (kernel portability rule)

## Diff semantics

`diff(from, to)` returns a deterministic list of semantic operations:

- `add_node`, `remove_node`, `update_node`
- `add_edge`, `remove_edge`, `update_edge`

Each op includes:
- `atom` selector (`node:<id>` or `edge:<id>`)
- `before` and/or `after` payload

Ops are sorted deterministically by `(atom, op)`.

## Merge semantics (3-way)

`merge(base, left, right)` performs atom-wise 3-way merge on nodes and edges.

Conflict taxonomy (examples):
- `edit_edit` — both sides edited an atom differently
- `delete_edit` — left deleted, right edited
- `edit_delete` — left edited, right deleted
- `add_add` — both sides added the atom differently

Merge output exposes `conflicts[]` with at least:
- `type`, `severity`, `selector`, `allowed_resolutions`
- deterministic `conflict_id`

This shape is compatible with the conformance harness’s semantic expectations.

## Validation rules and issue codes

`validate(state)` returns a kernel-shaped `ValidationResult`:

- `MISSING_OR_AMBIGUOUS_START_NODE` (error)
- `MISSING_END_NODE` (error)
- `ORPHAN_EDGE` (error)
- `MISSING_REQUIRED_FIELD` for task nodes missing `config.task_key` (error)
- `CYCLE_DETECTED` (error)
- `UNREACHABLE_NODE` (warning)

All issues must include at least one atom selector in `atoms[]` for localization.
