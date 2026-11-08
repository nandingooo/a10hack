import { forceSimulation, forceLink, forceManyBody, forceCollide, forceX, forceY } from 'd3-force';

// D3 mutates its inputs. Keep all simulation state separate from the audit model.
export function networkData(graph, previous = new Map()) {
  const degree = new Map(graph.nodes.map(node => [node.id, 0]));
  graph.edges.forEach(edge => {
    degree.set(edge.from, (degree.get(edge.from) || 0) + 1);
    degree.set(edge.to, (degree.get(edge.to) || 0) + 1);
  });
  const nodes = graph.nodes.map((node, index) => {
    const old = previous.get(node.id);
    const parent = node.parents.map(id => previous.get(id)).find(Boolean);
    const angle = index * 2.399963229728653;
    const radius = 16 * Math.sqrt(index + 1);
    return {
      id: node.id, degree: degree.get(node.id),
      x: old?.x ?? (parent ? parent.x + Math.cos(angle) * 24 : Math.cos(angle) * radius),
      y: old?.y ?? (parent ? parent.y + Math.sin(angle) * 24 : Math.sin(angle) * radius),
      vx: old?.vx || 0, vy: old?.vy || 0,
    };
  });
  const links = graph.edges.map(edge => ({ ...edge, source: edge.from, target: edge.to }));
  return { nodes, links, byId: new Map(nodes.map(node => [node.id, node])) };
}

export function networkSimulation(data) {
  return forceSimulation(data.nodes)
    .force('links', forceLink(data.links).id(node => node.id).distance(edge => edge.kind === 'evidence' ? 62 : 44))
    .force('charge', forceManyBody().strength(-100).distanceMax(650))
    .force('collision', forceCollide().radius(node => nodeRadius(node) + 7))
    .force('x', forceX(0).strength(0.025))
    .force('y', forceY(0).strength(0.025))
    .alphaDecay(0.035).velocityDecay(0.4).stop();
}

export const nodeRadius = node => Math.min(7, 2.6 + Math.sqrt(node.degree || 0) * 0.65);
export const screenPoint = (node, camera) => ({ x: node.x * camera.k + camera.x, y: node.y * camera.k + camera.y });
export const worldPoint = (point, camera) => ({ x: (point.x - camera.x) / camera.k, y: (point.y - camera.y) / camera.k });

export function zoomAt(camera, point, factor) {
  const k = Math.max(0.12, Math.min(8, camera.k * factor));
  const world = worldPoint(point, camera);
  return { k, x: point.x - world.x * k, y: point.y - world.y * k };
}

export function fitNetwork(nodes, width, height) {
  if (!nodes.length) return { x: width / 2, y: height / 2, k: 1 };
  let left = Infinity, right = -Infinity, top = Infinity, bottom = -Infinity;
  nodes.forEach(node => { left = Math.min(left, node.x); right = Math.max(right, node.x); top = Math.min(top, node.y); bottom = Math.max(bottom, node.y); });
  const padding = Math.min(72, width * 0.16, height * 0.16);
  const k = Math.max(0.12, Math.min(2, (width - padding * 2) / Math.max(100, right - left), (height - padding * 2) / Math.max(100, bottom - top)));
  return { k, x: width / 2 - (left + right) / 2 * k, y: height / 2 - (top + bottom) / 2 * k };
}

export function pickNode(nodes, point, camera) {
  let nearest = null, best = Infinity;
  for (const node of nodes) {
    const screen = screenPoint(node, camera);
    const distance = Math.hypot(screen.x - point.x, screen.y - point.y);
    if (distance <= Math.max(12, nodeRadius(node) * camera.k + 5) && distance < best) { nearest = node; best = distance; }
  }
  return nearest;
}
