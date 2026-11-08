// Pure provenance-graph model: gateway entries + decision events -> laid-out DAG,
// plus the backward traversal the guard's verdict is based on. No React here.

export const COLUMN_WIDTH = 210;
export const ROW_HEIGHT = 58;
export const NODE_WIDTH = 168;
export const NODE_HEIGHT = 40;
const PADDING = 24;

const shortName = target => {
  const text = String(target ?? '');
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : text || '(unknown)';
};

const sourceType = (kind, sensitivity) => (kind === 'action' ? 'action' : sensitivity === 'secret' ? 'secret' : 'source');

/** Visible risk of a node, used for colour and for "what tainted this decision". */
export function taint(node) {
  if (node.bait) return 'bait';
  if (node.sensitivity === 'secret') return 'secret';
  if (node.trust === 'untrusted' || node.trust === 'unknown') return 'untrusted';
  return 'clean';
}

function entryNode(entry) {
  const labels = entry.labels || {};
  return {
    id: entry.id, type: sourceType(entry.kind, labels.sensitivity), label: shortName(entry.target),
    target: entry.target, op: entry.op, trust: labels.trust, sensitivity: labels.sensitivity,
    bait: Boolean(labels.bait), ts: entry.ts ?? 0, parents: [...new Set(entry.parents || [])],
    verdict: entry.verdict, rule: entry.rule, basis: entry.metadata?.basis,
  };
}

function evidenceNode(item, fallbackTs) {
  return {
    id: item.id, type: sourceType('source', item.sensitivity), label: shortName(item.target),
    target: item.target, op: 'ReadFile', trust: item.trust, sensitivity: item.sensitivity,
    bait: false, ts: fallbackTs, parents: [...new Set(item.parents || [])], basis: item.basis,
  };
}

// An allowed ReadFile decision is redundant with the entry it creates; keep everything else.
const showsDecision = event => event.type === 'decision' && !(event.op === 'ReadFile' && event.decision === 'allow');

function collectNodes(entries, events) {
  const nodes = new Map();
  const byTarget = new Map();
  const add = node => {
    if (!node.id || nodes.has(node.id)) return;
    nodes.set(node.id, node);
    if (node.target && !byTarget.has(node.target)) byTarget.set(node.target, node.id);
  };
  entries.forEach(entry => add(entryNode(entry)));
  // Evidence may cite provisional (in-flight) entries whose IDs are never committed: resolve them
  // to the committed entry for the same resource, or merge them into one node per resource.
  const resolve = (item, ts) => {
    if (nodes.has(item.id)) return item.id;
    if (byTarget.has(item.target)) return byTarget.get(item.target);
    add(evidenceNode({ ...item, id: item.id || 'evidence:' + item.target }, ts));
    return item.id || 'evidence:' + item.target;
  };
  for (const event of events) {
    if (event.type !== 'decision') continue;
    const parents = (event.evidence || []).map(item => resolve(item, (event.ts ?? 0) - 1e-6));
    if (!showsDecision(event)) continue;
    add({
      id: 'decision:' + event.seq, type: 'decision', label: event.op || 'action', target: event.target,
      op: event.op, decision: event.decision, rule: event.rule, reason: event.reason, ts: event.ts ?? 0,
      seq: event.seq, parents: [...new Set(parents.filter(Boolean))],
    });
  }
  return nodes;
}

function depths(nodes) {
  const memo = new Map();
  const visiting = new Set();
  const depthOf = id => {
    if (memo.has(id)) return memo.get(id);
    if (visiting.has(id)) return 0; // cycle guard: provenance should be acyclic, but never hang
    visiting.add(id);
    const parents = nodes.get(id).parents.filter(p => nodes.has(p) && p !== id);
    const depth = parents.length ? 1 + Math.max(...parents.map(depthOf)) : 0;
    visiting.delete(id);
    memo.set(id, depth);
    return depth;
  };
  nodes.forEach((_, id) => depthOf(id));
  return memo;
}

/** Build a column-per-depth layout. Returns new objects; inputs are not mutated. */
export function buildGraph(entries = [], events = []) {
  const nodes = collectNodes(entries, events);
  const depth = depths(nodes);
  const ordered = [...nodes.values()].sort((a, b) => a.ts - b.ts || String(a.id).localeCompare(String(b.id)));
  const rowsUsed = new Map();
  const laidOut = ordered.map((node, order) => {
    const column = depth.get(node.id);
    const row = rowsUsed.get(column) || 0;
    rowsUsed.set(column, row + 1);
    return { ...node, order, column, row, x: PADDING + column * COLUMN_WIDTH, y: PADDING + row * ROW_HEIGHT };
  });
  const byId = new Map(laidOut.map(node => [node.id, node]));
  const edges = laidOut.flatMap(node => node.parents.filter(p => byId.has(p) && p !== node.id).map(parent => ({
    id: parent + '->' + node.id, from: parent, to: node.id,
    kind: node.type === 'decision' ? 'evidence' : 'provenance',
  })));
  const columns = Math.max(0, ...laidOut.map(n => n.column + 1));
  const rows = Math.max(0, ...rowsUsed.values());
  return {
    nodes: laidOut, edges, byId,
    width: PADDING * 2 + Math.max(0, columns - 1) * COLUMN_WIDTH + NODE_WIDTH,
    height: PADDING * 2 + Math.max(0, rows - 1) * ROW_HEIGHT + NODE_HEIGHT,
  };
}

/**
 * Breadth-first walk backwards from a node over its parents: the same question the guard
 * asks ("what context could have reached this action?"). levels[0] = [start].
 */
export function traceBack(graph, startId) {
  if (!graph.byId.has(startId)) return { levels: [], edges: [], tainted: [] };
  const seen = new Set([startId]);
  const levels = [[startId]];
  const edges = [];
  while (true) {
    const next = [];
    for (const id of levels[levels.length - 1]) {
      for (const parent of graph.byId.get(id).parents) {
        if (!graph.byId.has(parent)) continue;
        edges.push({ id: parent + '->' + id, level: levels.length });
        if (!seen.has(parent)) { seen.add(parent); next.push(parent); }
      }
    }
    if (!next.length) break;
    levels.push(next);
  }
  const tainted = [...seen].filter(id => id !== startId && taint(graph.byId.get(id)) !== 'clean');
  return { levels, edges, tainted };
}
