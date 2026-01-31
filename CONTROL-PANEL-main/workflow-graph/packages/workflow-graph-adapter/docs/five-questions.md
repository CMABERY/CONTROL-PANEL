# Workflow Graph Domain Walkthrough: Five Questions (C layer)

This answers the design-space questions **before** writing code.

## 1) Interaction surface

**Primary surface:** a workflow builder canvas (node-link graph editor).  
**Secondary surfaces:** a run/debug view (execution traces), and a review view (PR-style diff & comments).

Implication: diffs and merges must be legible **on the canvas**, not only as JSON.

## 2) User-perceived atom

**Atom:** a *graph atom* with stable identity:
- `node:<nodeId>` — a workflow step
- `edge:<edgeId>` — a directed connection

Why: users reason about “this step” and “this connection”, not lines in a file.

## 3) Diff perception channel

**Channel:** visual overlays on the graph:
- added nodes/edges: highlighted
- removed nodes/edges: ghosted
- modified node config: badges + inspector panel diff
- modified edge conditions: inline label highlight

Text diffs still exist, but only as a *drill-down*, not the primary channel.

## 4) What users fear

1. Breaking production automations (silent semantic changes)
2. Losing work / not being able to recover after an experiment
3. Merge “corrupting” a graph (half-applied edits, dangling edges)

Design consequence: trust comes from **visibility + reversibility**, plus deterministic identity.

## 5) Minimum viable loop

The loop must stay lightweight:

1. **Change** a node/edge
2. **Checkpoint** (named) with a short summary
3. **Inspect** (canvas overlay diff, plus drill-down)
4. **Restore** (safe reset / undo / reflog recovery)

The loop is successful when users can confidently experiment without fear.

## Domain-specific addendum: staging

Staging must freeze intent (index overlay):
- a staged patch references `from_hash` (the exact base state you staged against)
- staging should not chase live edits automatically

That prevents “I staged X but it morphed while I kept editing” surprises.
