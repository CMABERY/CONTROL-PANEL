/**
 * Workflow Graph Adapter (Reference)
 *
 * Domain: workflow-builder graphs (nodes + directed edges).
 *
 * Goal: demonstrate an implementable adapter that passes the full conformance stack:
 * - deterministic canonicalization (integer-only kernel numbers)
 * - domain goldens (canonical bytes + SHA-256)
 * - diff/merge determinism
 * - validate() returning kernel-shaped ValidationResult
 * - semantic expectations for conflicts + validation issues
 */

import { canonicalize } from 'flowversion-conformance';
import { createHash } from 'node:crypto';

function sha256HexString(s) {
  return createHash('sha256').update(s).digest('hex');
}

const UUID_NAMESPACE_DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error(`Invalid UUID: ${uuid}`);
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToUuid(bytes) {
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

function uuidV5(name, namespaceUuid = UUID_NAMESPACE_DNS) {
  const ns = uuidToBytes(namespaceUuid);
  const nameBytes = new TextEncoder().encode(name);

  const buf = Buffer.concat([Buffer.from(ns), Buffer.from(nameBytes)]);
  const hash = createHash('sha1').update(buf).digest(); // 20 bytes
  const bytes = Uint8Array.from(hash.slice(0, 16));

  // Set version (5)
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  // Set variant (RFC 4122)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  return bytesToUuid(bytes);
}

function stableUUID(prefix, obj) {
  const json = JSON.stringify(canonicalize(obj));
  return uuidV5(`${prefix}:${json}`);
}

function isPlainObject(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

function asString(x, { field }) {
  if (typeof x === 'string') return x;
  throw new Error(`Expected string for ${field}`);
}

function normalizeNode(node) {
  if (!isPlainObject(node)) throw new Error('Node must be an object');
  const id = asString(node.id, { field: 'node.id' });

  const type = (typeof node.type === 'string' && node.type.trim()) ? node.type.trim() : 'task';
  const label = (typeof node.label === 'string') ? node.label : undefined;

  const config = isPlainObject(node.config) ? node.config : {};
  const meta = isPlainObject(node.meta) ? node.meta : undefined;

  // Keep node payload domain-flexible, but enforce kernel portability at the final canonicalize() step.
  // If domains need floats (e.g. UI coordinates), they must quantize before persisting.
  const out = {
    config,
    id,
    label,
    meta,
    type,
  };

  // Omit undefined keys, then base-canonicalize.
  return canonicalize(out);
}

function normalizeEdge(edge) {
  if (!isPlainObject(edge)) throw new Error('Edge must be an object');
  const from = asString(edge.from, { field: 'edge.from' });
  const to = asString(edge.to, { field: 'edge.to' });

  const id = (typeof edge.id === 'string' && edge.id.trim())
    ? edge.id.trim()
    : `${from}->${to}`;

  const label = (typeof edge.label === 'string') ? edge.label : undefined;
  const type = (typeof edge.type === 'string' && edge.type.trim()) ? edge.type.trim() : 'flow';

  const condition = isPlainObject(edge.condition) ? edge.condition : undefined;
  const meta = isPlainObject(edge.meta) ? edge.meta : undefined;

  const out = {
    condition,
    from,
    id,
    label,
    meta,
    to,
    type,
  };

  return canonicalize(out);
}

function normalizeGraph(graph) {
  const nodesIn = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edgesIn = Array.isArray(graph.edges) ? graph.edges : [];

  const nodes = nodesIn.map(normalizeNode).sort((a, b) => a.id.localeCompare(b.id));
  const edges = edgesIn.map(normalizeEdge).sort((a, b) => a.id.localeCompare(b.id));

  const meta = isPlainObject(graph.meta) ? graph.meta : undefined;
  const name = (typeof graph.name === 'string') ? graph.name : undefined;

  const out = {
    edges,
    kind: 'workflow_graph@1',
    meta,
    name,
    nodes,
  };

  return canonicalize(out);
}

function looksLikeGraph(value) {
  return isPlainObject(value) && (Array.isArray(value.nodes) || Array.isArray(value.edges) || value.kind === 'workflow_graph@1');
}

// --- Public Adapter API ---

/**
 * Domain canonicalization.
 *
 * Rule: adapter returns already-base-canonical output.
 * That means:
 *   canonicalize(canonicalizeDomain(x)) === canonicalizeDomain(x)
 */
export function canonicalizeDomain(value) {
  if (looksLikeGraph(value)) {
    return normalizeGraph(value);
  }
  // Pass-through for non-domain values (lets the harness run its generic invariants).
  return canonicalize(value);
}

/**
 * Domain diff: returns a deterministic list of semantic ops.
 *
 * Output is domain-specific, but must be JSON-stable and deterministic.
 */
export function diff(fromState, toState, _options = undefined) {
  const from = canonicalizeDomain(fromState);
  const to = canonicalizeDomain(toState);

  if (!looksLikeGraph(from) || !looksLikeGraph(to)) {
    // For non-graph inputs, fallback to "replace".
    return canonicalize([{ op: 'replace', atom: 'value:root', before: from, after: to }]);
  }

  const fromNodes = new Map(from.nodes.map((n) => [n.id, n]));
  const toNodes = new Map(to.nodes.map((n) => [n.id, n]));
  const fromEdges = new Map(from.edges.map((e) => [e.id, e]));
  const toEdges = new Map(to.edges.map((e) => [e.id, e]));

  /** @type {any[]} */
  const ops = [];

  // Nodes
  const nodeIds = Array.from(new Set([...fromNodes.keys(), ...toNodes.keys()])).sort();
  for (const id of nodeIds) {
    const a = fromNodes.get(id);
    const b = toNodes.get(id);
    const atom = `node:${id}`;

    if (!a && b) {
      ops.push({ op: 'add_node', atom, after: b });
    } else if (a && !b) {
      ops.push({ op: 'remove_node', atom, before: a });
    } else if (a && b) {
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        ops.push({ op: 'update_node', atom, before: a, after: b });
      }
    }
  }

  // Edges
  const edgeIds = Array.from(new Set([...fromEdges.keys(), ...toEdges.keys()])).sort();
  for (const id of edgeIds) {
    const a = fromEdges.get(id);
    const b = toEdges.get(id);
    const atom = `edge:${id}`;

    if (!a && b) {
      ops.push({ op: 'add_edge', atom, after: b });
    } else if (a && !b) {
      ops.push({ op: 'remove_edge', atom, before: a });
    } else if (a && b) {
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        ops.push({ op: 'update_edge', atom, before: a, after: b });
      }
    }
  }

  // Deterministic ordering: by atom then op string.
  ops.sort((x, y) => {
    const ax = String(x.atom);
    const ay = String(y.atom);
    if (ax !== ay) return ax.localeCompare(ay);
    return String(x.op).localeCompare(String(y.op));
  });

  return canonicalize(ops);
}

/**
 * Three-way merge for workflow graphs.
 *
 * Returns:
 * {
 *   merged: <workflow_graph@1>,
 *   conflicts: [ { conflict_id, type, selector, severity, allowed_resolutions, default_resolution? , reason? } ]
 * }
 */
export function merge(baseState, leftState, rightState, _options = undefined) {
  const base = canonicalizeDomain(baseState);
  const left = canonicalizeDomain(leftState);
  const right = canonicalizeDomain(rightState);

  if (!looksLikeGraph(base) || !looksLikeGraph(left) || !looksLikeGraph(right)) {
    // For non-graph inputs: last-writer-wins with edit_edit conflict when both differ from base.
    const conflicts = [];
    let mergedVal = left;
    if (JSON.stringify(left) !== JSON.stringify(right)) {
      if (JSON.stringify(base) !== JSON.stringify(left) && JSON.stringify(base) !== JSON.stringify(right)) {
        conflicts.push(makeConflict({
          type: 'edit_edit',
          selector: 'value:root',
          severity: 'error',
          reason: 'Both sides edited value:root differently',
          allowed_resolutions: ['take_left', 'take_right', 'take_base'],
        }, base, left, right));
        mergedVal = base;
      } else if (JSON.stringify(base) === JSON.stringify(left)) {
        mergedVal = right;
      } else {
        mergedVal = left;
      }
    }
    return canonicalize({ merged: mergedVal, conflicts });
  }

  const merged = { ...base, nodes: [], edges: [] };
  const conflicts = [];

  const bNodes = new Map(base.nodes.map((n) => [n.id, n]));
  const lNodes = new Map(left.nodes.map((n) => [n.id, n]));
  const rNodes = new Map(right.nodes.map((n) => [n.id, n]));

  const nodeIds = Array.from(new Set([...bNodes.keys(), ...lNodes.keys(), ...rNodes.keys()])).sort();

  for (const id of nodeIds) {
    const b = bNodes.get(id);
    const l = lNodes.get(id);
    const r = rNodes.get(id);
    const selector = `node:${id}`;

    const { value, conflict } = threeWayAtomMerge({ base: b, left: l, right: r, selector });
    if (conflict) conflicts.push(conflict);
    if (value) merged.nodes.push(value);
  }

  const bEdges = new Map(base.edges.map((e) => [e.id, e]));
  const lEdges = new Map(left.edges.map((e) => [e.id, e]));
  const rEdges = new Map(right.edges.map((e) => [e.id, e]));

  const edgeIds = Array.from(new Set([...bEdges.keys(), ...lEdges.keys(), ...rEdges.keys()])).sort();

  for (const id of edgeIds) {
    const b = bEdges.get(id);
    const l = lEdges.get(id);
    const r = rEdges.get(id);
    const selector = `edge:${id}`;

    const { value, conflict } = threeWayAtomMerge({ base: b, left: l, right: r, selector });
    if (conflict) conflicts.push(conflict);
    if (value) merged.edges.push(value);
  }

  // Normalize final merged graph (sort nodes/edges, enforce base-canonical output).
  const mergedCanon = canonicalizeDomain(merged);

  return canonicalize({ merged: mergedCanon, conflicts });
}

function makeConflict(spec, baseVal, leftVal, rightVal) {
  const payload = {
    spec,
    base: baseVal ?? null,
    left: leftVal ?? null,
    right: rightVal ?? null,
  };

  const conflict_id = stableUUID('conflict', payload);

  const out = {
    allowed_resolutions: spec.allowed_resolutions ?? ['take_left', 'take_right', 'take_base'],
    conflict_id,
    default_resolution: spec.default_resolution,
    reason: spec.reason,
    selector: spec.selector,
    severity: spec.severity,
    type: spec.type,
  };

  // Omit undefined default_resolution/reason via canonicalize().
  return canonicalize(out);
}

function threeWayAtomMerge({ base, left, right, selector }) {
  const jb = base ? JSON.stringify(base) : null;
  const jl = left ? JSON.stringify(left) : null;
  const jr = right ? JSON.stringify(right) : null;

  // Helper comparisons
  const eqBL = jb === jl;
  const eqBR = jb === jr;
  const eqLR = jl === jr;

  // Cases
  if (!base && !left && !right) return { value: null, conflict: null };

  // Added in both
  if (!base && left && right) {
    if (eqLR) return { value: left, conflict: null };

    const conflict = makeConflict({
      type: 'add_add',
      selector,
      severity: 'warning',
      reason: 'Both sides added the atom differently',
      allowed_resolutions: ['take_left', 'take_right', 'manual'],
      default_resolution: 'take_left',
    }, base, left, right);

    // For warnings, apply default resolution.
    return { value: left, conflict };
  }

  // Deleted in both
  if (base && !left && !right) return { value: null, conflict: null };

  // Base existed, one side missing
  if (base && !left && right) {
    if (eqBR) {
      // Left deleted, right unchanged -> accept delete
      return { value: null, conflict: null };
    }

    const conflict = makeConflict({
      type: 'delete_edit',
      selector,
      severity: 'error',
      reason: 'Left deleted the atom while right edited it',
      allowed_resolutions: ['take_delete', 'take_right', 'take_base', 'manual'],
    }, base, left, right);

    // For errors, preserve base by default.
    return { value: base, conflict };
  }

  if (base && left && !right) {
    if (eqBL) {
      // Right deleted, left unchanged -> accept delete
      return { value: null, conflict: null };
    }

    const conflict = makeConflict({
      type: 'edit_delete',
      selector,
      severity: 'error',
      reason: 'Right deleted the atom while left edited it',
      allowed_resolutions: ['take_delete', 'take_left', 'take_base', 'manual'],
    }, base, left, right);

    return { value: base, conflict };
  }

  // All present
  if (base && left && right) {
    if (eqLR) return { value: left, conflict: null };
    if (eqBL) return { value: right, conflict: null };
    if (eqBR) return { value: left, conflict: null };

    const conflict = makeConflict({
      type: 'edit_edit',
      selector,
      severity: 'error',
      reason: 'Both sides edited the atom differently',
      allowed_resolutions: ['take_left', 'take_right', 'take_base', 'manual'],
    }, base, left, right);

    return { value: base, conflict };
  }

  // Fallback: prefer left
  return { value: left ?? right ?? base ?? null, conflict: null };
}

/**
 * Domain validation.
 *
 * Returns kernel-shaped ValidationResult:
 * {
 *   v: 1,
 *   valid: boolean,
 *   issues: [ValidationIssue...],
 *   state_hash?: sha256
 * }
 */
export function validate(state, _options = undefined) {
  const g = canonicalizeDomain(state);

  /** @type {any[]} */
  const issues = [];

  if (!looksLikeGraph(g)) {
    // Treat non-graph value as valid (this is a reference adapter, not a prison).
    return canonicalize({
      v: 1,
      valid: true,
      issues: [],
      state_hash: sha256HexString(JSON.stringify(g)).toLowerCase(),
    });
  }

  // Compute stable state hash on canonical bytes.
  const state_hash = sha256HexString(JSON.stringify(g)).toLowerCase();

  const nodesById = new Map(g.nodes.map((n) => [n.id, n]));
  const edgesById = new Map(g.edges.map((e) => [e.id, e]));

  const atomWorkflow = 'workflow:root';

  // Rule: exactly one start node
  const startNodes = g.nodes.filter((n) => n.type === 'start');
  if (startNodes.length !== 1) {
    issues.push(makeIssue({
      code: 'MISSING_OR_AMBIGUOUS_START_NODE',
      message: `Expected exactly 1 start node, found ${startNodes.length}`,
      severity: 'error',
      atoms: startNodes.length ? startNodes.map((n) => `node:${n.id}`) : [atomWorkflow],
    }));
  }

  // Rule: at least one end node
  const endNodes = g.nodes.filter((n) => n.type === 'end');
  if (endNodes.length < 1) {
    issues.push(makeIssue({
      code: 'MISSING_END_NODE',
      message: 'Expected at least 1 end node',
      severity: 'error',
      atoms: [atomWorkflow],
    }));
  }

  // Rule: edges reference existing nodes
  for (const e of g.edges) {
    const fromOk = nodesById.has(e.from);
    const toOk = nodesById.has(e.to);
    if (!fromOk || !toOk) {
      const missing = [];
      if (!fromOk) missing.push(`node:${e.from}`);
      if (!toOk) missing.push(`node:${e.to}`);
      issues.push(makeIssue({
        code: 'ORPHAN_EDGE',
        message: `Edge references missing node(s): ${missing.join(', ')}`,
        severity: 'error',
        atoms: [`edge:${e.id}`, ...missing],
      }));
    }
  }

  // Rule: task nodes require config.task_key
  for (const n of g.nodes) {
    if (n.type === 'task') {
      const taskKey = n.config && typeof n.config.task_key === 'string' ? n.config.task_key : null;
      if (!taskKey) {
        issues.push(makeIssue({
          code: 'MISSING_REQUIRED_FIELD',
          message: 'Task node requires config.task_key',
          severity: 'error',
          atoms: [`node:${n.id}`],
          region_hint: 'node.config.task_key',
          suggested_fix: { set: { 'config.task_key': '<task_key>' } },
        }));
      }
    }
  }

  // Rule: detect cycles (directed)
  const cycle = findCycle(nodesById, g.edges);
  if (cycle) {
    const atoms = cycle.map((id) => `node:${id}`);
    issues.push(makeIssue({
      code: 'CYCLE_DETECTED',
      message: `Cycle detected: ${cycle.join(' -> ')}`,
      severity: 'error',
      atoms: atoms.length ? atoms : [atomWorkflow],
    }));
  }

  // Rule: reachability from start (if start exists uniquely)
  if (startNodes.length === 1) {
    const reachable = reachableFrom(startNodes[0].id, g.edges);
    for (const id of nodesById.keys()) {
      if (!reachable.has(id)) {
        issues.push(makeIssue({
          code: 'UNREACHABLE_NODE',
          message: `Node is not reachable from start: ${id}`,
          severity: 'warning',
          atoms: [`node:${id}`],
        }));
      }
    }
  }

  const valid = issues.every((i) => i.severity !== 'error');

  return canonicalize({
    v: 1,
    valid,
    issues,
    state_hash,
  });
}

function makeIssue({ code, message, severity, atoms, anchors, region_hint, suggested_fix }) {
  const issuePayload = { code, message, severity, atoms, anchors, region_hint, suggested_fix };
  const issue_id = stableUUID('issue', issuePayload);

  const out = {
    anchors,
    atoms,
    code,
    issue_id,
    message,
    region_hint,
    severity,
    suggested_fix,
  };

  return canonicalize(out);
}

// --- Graph utilities ---

function reachableFrom(startId, edges) {
  const adj = new Map();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e.to);
  }

  const seen = new Set();
  const stack = [startId];
  while (stack.length) {
    const cur = stack.pop();
    if (seen.has(cur)) continue;
    seen.add(cur);
    const next = adj.get(cur) || [];
    for (const n of next) stack.push(n);
  }
  return seen;
}

function findCycle(nodesById, edges) {
  // Standard DFS cycle detection for directed graphs.
  const adj = new Map();
  for (const id of nodesById.keys()) adj.set(id, []);
  for (const e of edges) {
    if (adj.has(e.from)) adj.get(e.from).push(e.to);
  }

  const visiting = new Set();
  const visited = new Set();
  const parent = new Map();

  function dfs(u) {
    visiting.add(u);
    for (const v of adj.get(u) || []) {
      if (!visited.has(v)) {
        if (visiting.has(v)) {
          // found back-edge u -> v; reconstruct cycle v ... u ... v
          parent.set(v, u);
          return reconstructCycle(v, u, parent);
        }
        parent.set(v, u);
        const res = dfs(v);
        if (res) return res;
      }
    }
    visiting.delete(u);
    visited.add(u);
    return null;
  }

  function reconstructCycle(start, end, parentMap) {
    // build path end -> ... -> start
    const path = [start];
    let cur = end;
    while (cur !== start && cur != null) {
      path.push(cur);
      cur = parentMap.get(cur);
      if (path.length > 10000) break;
    }
    path.reverse();
    path.push(start);
    return path;
  }

  for (const id of nodesById.keys()) {
    if (!visited.has(id)) {
      const res = dfs(id);
      if (res) return res;
    }
  }
  return null;
}
