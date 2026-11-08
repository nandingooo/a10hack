import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, nodePresentation, taint, traceBack } from './provenanceGraph.js';

const entry = (id, target, ts, { trust = 'trusted', sensitivity = 'public', parents = [], kind = 'source' } = {}) => ({
  id, target, ts, kind, op: 'ReadFile', parents, labels: { trust, sensitivity, bait: false }, metadata: {},
});

const readme = entry('e1', '/work/vendor/README.md', 1, { trust: 'untrusted' });
const notes = entry('e2', '/work/notes.txt', 2, { trust: 'untrusted', parents: ['e1'] });
const env = entry('e3', '/work/.env', 3, { sensitivity: 'secret' });
const block = {
  type: 'decision', seq: 9, ts: 4, op: 'RunCommand', target: '[shell command]', decision: 'block',
  rule: 'untrusted_destructive', evidence: [{ id: 'e2' }, { id: 'e3' }],
};

test('preserves sources, derived artifacts and decisions in creation order', () => {
  const graph = buildGraph([readme, notes, env], [block]);
  assert.deepEqual(graph.nodes.map(node => node.id), ['e1', 'e2', 'e3', 'decision:9']);
  assert.deepEqual(graph.nodes.map(node => node.order), [0, 1, 2, 3]);
  assert.deepEqual(graph.edges.map(e => e.id).sort(), ['e1->e2', 'e2->decision:9', 'e3->decision:9']);
});

test('hides allowed ReadFile decisions because the entry already represents the read', () => {
  const allowedRead = { type: 'decision', seq: 1, ts: 1, op: 'ReadFile', decision: 'allow', evidence: [] };
  const graph = buildGraph([readme], [allowedRead]);
  assert.equal(graph.byId.has('decision:1'), false);
});

test('creates nodes from decision evidence when entries are unavailable (archived run)', () => {
  const archived = { ...block, evidence: [{ id: 'x1', target: '/work/.env', trust: 'trusted', sensitivity: 'secret', parents: [] }] };
  const graph = buildGraph([], [archived]);
  assert.equal(graph.byId.get('x1').type, 'secret');
  assert.deepEqual(graph.byId.get('decision:9').parents, ['x1']);
});

test('resolves provisional evidence IDs to the committed entry for the same resource', () => {
  const provisional = { ...block, seq: 5, evidence: [{ id: 'tmp-1', target: '/work/.env', sensitivity: 'secret' }] };
  const unknown = { ...block, seq: 6, evidence: [{ id: 'tmp-2', target: '/work/x' }, { id: 'tmp-3', target: '/work/x' }] };
  const graph = buildGraph([env], [provisional, unknown]);
  assert.deepEqual(graph.byId.get('decision:5').parents, ['e3']);
  assert.equal(graph.byId.has('tmp-1'), false);
  assert.deepEqual(graph.byId.get('decision:6').parents, ['tmp-2']);
});

test('traceBack walks parents level by level and reports tainted context', () => {
  const graph = buildGraph([readme, notes, env], [block]);
  const trace = traceBack(graph, 'decision:9');
  assert.deepEqual(trace.levels, [['decision:9'], ['e2', 'e3'], ['e1']]);
  assert.deepEqual(trace.tainted.sort(), ['e1', 'e2', 'e3']);
  assert.deepEqual(trace.edges.map(e => [e.id, e.level]), [['e2->decision:9', 1], ['e3->decision:9', 1], ['e1->e2', 2]]);
});

test('survives cycles and unknown starts', () => {
  const a = entry('a', 'a', 1, { parents: ['b'] });
  const b = entry('b', 'b', 2, { parents: ['a'] });
  const graph = buildGraph([a, b], []);
  assert.equal(graph.nodes.length, 2);
  assert.ok(traceBack(graph, 'a').levels.length <= 2);
  assert.deepEqual(traceBack(graph, 'missing').levels, []);
});

test('taint classifies bait, secret, untrusted and clean', () => {
  assert.equal(taint({ bait: true }), 'bait');
  assert.equal(taint({ sensitivity: 'secret' }), 'secret');
  assert.equal(taint({ trust: 'unknown' }), 'untrusted');
  assert.equal(taint({ trust: 'trusted', sensitivity: 'public' }), 'clean');
});

test('does not mutate its inputs', () => {
  const input = [structuredClone(readme)];
  const snapshot = structuredClone(input);
  buildGraph(input, []);
  assert.deepEqual(input, snapshot);
});

test('displays the file path and both assigned label axes', () => {
  const source = entry('secret', '/work/config/.env', 1, { trust: 'untrusted', sensitivity: 'secret' });
  source.metadata.exposure_status = 'exposed';
  const info = nodePresentation(buildGraph([source], []).byId.get('secret'));
  assert.equal(info.title, '.env');
  assert.equal(info.resource, '/work/config/.env');
  assert.equal(info.caption, 'Tags: untrusted · secret');
  assert.equal(info.detail, 'ReadFile · exposed');
});

test('network decisions retain the destination and verdict without claiming a file read', () => {
  const event = { ...block, op: 'NetworkRequest', target: 'claude.ai', decision: 'allow', rule: 'no_dangerous_flow', context: { untrusted: true, secret: false } };
  const info = nodePresentation(buildGraph([], [event]).byId.get('decision:9'));
  assert.equal(info.title, 'NetworkRequest');
  assert.equal(info.resource, 'claude.ai');
  assert.equal(info.caption, 'ALLOW · no_dangerous_flow');
  assert.deepEqual(info.tags, []);
  assert.match(info.detail, /untrusted/);
});

test('unreported labels remain unknown and inferred exposure stays explicit', () => {
  const source = { id: 'partial', kind: 'source', op: 'ReadFile', target: '/work/notes.txt', metadata: { exposure_status: 'unknown' } };
  const node = buildGraph([source], []).byId.get('partial');
  const info = nodePresentation(node);
  assert.equal(info.caption, 'Tags: unknown trust · unknown sensitivity');
  assert.equal(info.detail, 'ReadFile · inferred exposure');
  assert.equal(taint(node), 'untrusted');
});

test('isolated sources stay isolated and missing parents never become phantom links', () => {
  const graph = buildGraph([readme, env, entry('partial', '/work/partial.txt', 4, { parents: ['missing', 'partial'] })]);
  assert.equal(graph.edges.length, 0);
  assert.equal(graph.nodes.length, 3);
});
