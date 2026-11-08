// Pure audit model and backward evidence traversal. Spatial layout lives separately.

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
  if (node.trust !== 'trusted') return 'untrusted';
  return 'clean';
}

/** Keep resource labels separate from an action's verdict or accumulated context. */
export function nodePresentation(node) {
  const decision = node.type === 'decision';
  const inferred = /infer|proposed|inflight/.test(node.basis || '') || node.exposureStatus === 'unknown';
  const exposure = inferred ? 'inferred exposure'
    : node.exposureStatus === 'exposed' ? 'exposed'
      : node.exposureStatus === 'none' ? 'no content exposed' : 'exposure not reported';
  const tags = [node.trust || 'unknown trust', node.sensitivity || 'unknown sensitivity'];
  if (node.bait) tags.push('bait');
  return {
    title: node.label || node.op || 'Resource',
    resource: node.target || 'Resource not reported',
    caption: decision ? `${(node.decision || 'unknown').toUpperCase()} · ${node.rule || 'rule not reported'}` : `Tags: ${tags.join(' · ')}`,
    detail: decision ? (node.context
      ? `Context: ${node.context.untrusted ? 'untrusted' : 'no untrusted tag'} · ${node.context.secret ? 'secret' : 'no secret tag'}`
      : 'Context tags not reported') : `${node.op || 'Source'} · ${exposure}`,
    tags: decision ? [] : tags,
  };
}

function entryNode(entry) {
  const labels = entry.labels || {};
  return {
    id: entry.id, type: sourceType(entry.kind, labels.sensitivity), label: shortName(entry.target),
    target: entry.target, op: entry.op, trust: labels.trust, sensitivity: labels.sensitivity,
    bait: Boolean(labels.bait), ts: entry.ts ?? 0, parents: [...new Set(entry.parents || [])],
    verdict: entry.verdict, rule: entry.rule, basis: entry.metadata?.basis,
    exposureStatus: entry.metadata?.exposure_status, origin: entry.origin,
  };
}

function evidenceNode(item, fallbackTs) {
  return {
    id: item.id, type: sourceType('source', item.sensitivity), label: shortName(item.target),
    target: item.target, op: item.op || (/^(?:[/\\]|[A-Za-z]:[/\\])/.test(item.target || '') ? 'ReadFile' : 'Source'), trust: item.trust, sensitivity: item.sensitivity,
    bait: Boolean(item.bait), ts: fallbackTs, parents: [...new Set(item.parents || [])], basis: item.basis,
    exposureStatus: item.exposure_status, origin: item.origin,
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
      seq: event.seq, parents: [...new Set(parents.filter(Boolean))], context: event.context,
    });
  }
  return nodes;
}

/** Build recorded topology in creation order. Never invent links from proximity or time. */
export function buildGraph(entries = [], events = []) {
  const nodes = collectNodes(entries, events);
  const ordered = [...nodes.values()].sort((a, b) => a.ts - b.ts || String(a.id).localeCompare(String(b.id)));
  const model = ordered.map((node, order) => ({ ...node, order }));
  const byId = new Map(model.map(node => [node.id, node]));
  const edges = model.flatMap(node => node.parents.filter(p => byId.has(p) && p !== node.id).map(parent => ({
    id: parent + '->' + node.id, from: parent, to: node.id,
    kind: node.type === 'decision' ? 'evidence' : 'provenance',
  })));
  return { nodes: model, edges, byId };
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
