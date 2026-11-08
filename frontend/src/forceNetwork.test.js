import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph } from './provenanceGraph.js';
import { fitNetwork, networkData, networkSimulation, pickNode, screenPoint, worldPoint, zoomAt } from './forceNetwork.js';

const fixture = () => buildGraph([
  { id: 'readme', target: '/work/README.md', ts: 1, labels: { trust: 'untrusted', sensitivity: 'public' } },
  { id: 'secret', target: '/work/.env', ts: 2, labels: { trust: 'trusted', sensitivity: 'secret' } },
  { id: 'report', target: '/work/report.txt', ts: 3, parents: ['readme', 'secret'], labels: { trust: 'untrusted', sensitivity: 'secret' } },
], [{ type: 'decision', seq: 4, ts: 4, op: 'RunCommand', decision: 'block', evidence: [{ id: 'report' }, { id: 'secret' }] }]);

test('force layout retains only recorded relationships and never mutates audit data', () => {
  const graph = fixture(), before = JSON.stringify(graph.nodes);
  const data = networkData(graph), simulation = networkSimulation(data);
  simulation.tick(140); simulation.stop();
  assert.equal(JSON.stringify(graph.nodes), before);
  assert.deepEqual(data.links.map(link => link.id), graph.edges.map(edge => edge.id));
  for (const node of data.nodes) { assert.ok(Number.isFinite(node.x)); assert.ok(Number.isFinite(node.y)); }
  assert.ok(data.nodes.some(node => node.x !== graph.byId.get(node.id).x));
});

test('live refresh preserves existing positions and seeds new nodes beside their parent', () => {
  const graph = fixture(), previous = networkData(graph).byId;
  previous.get('secret').x = 123; previous.get('secret').y = -65;
  previous.delete('report');
  const next = networkData(graph, previous);
  assert.equal(next.byId.get('secret').x, 123);
  assert.equal(next.byId.get('secret').y, -65);
  assert.equal(graph.byId.get('secret').x === 123, false);
  assert.ok(Math.hypot(next.byId.get('report').x - previous.get('readme').x, next.byId.get('report').y - previous.get('readme').y) < 25);
});

test('pointer-centered zoom keeps the world point under the cursor and clamps extremes', () => {
  const camera = { k: 1.2, x: 54, y: -12 }, cursor = { x: 200, y: 150 };
  const world = worldPoint(cursor, camera), next = zoomAt(camera, cursor, 2);
  assert.deepEqual(screenPoint(world, next), cursor);
  assert.equal(zoomAt(next, cursor, 1e5).k, 8);
  assert.equal(zoomAt(next, cursor, 1e-5).k, 0.12);
});

test('fit and hit testing work at mobile dimensions, including empty and single nodes', () => {
  const nodes = [{ id: 'a', x: -100, y: -80 }, { id: 'b', x: 100, y: 80 }];
  const camera = fitNetwork(nodes, 320, 420);
  for (const node of nodes) {
    const point = screenPoint(node, camera);
    assert.ok(point.x > 0 && point.x < 320 && point.y > 0 && point.y < 420);
    assert.equal(pickNode(nodes, point, camera).id, node.id);
  }
  assert.equal(pickNode(nodes, { x: 0, y: 0 }, camera), null);
  assert.equal(fitNetwork([], 320, 420).k, 1);
  assert.ok(Number.isFinite(fitNetwork([{ x: 0, y: 0 }], 320, 420).k));
});
