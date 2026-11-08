import React, { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { fitNetwork, networkData, networkSimulation, nodeRadius, pickNode, screenPoint, worldPoint, zoomAt } from './forceNetwork.js';
import { nodePresentation, taint } from './provenanceGraph.js';

const colorKey = node => node.type === 'decision' ? node.decision === 'allow' ? 'clean' : node.decision === 'block' ? 'untrusted' : 'secret' : taint(node);

/** Canvas keeps dense evidence networks responsive without thousands of SVG elements. */
export default forwardRef(function ForceNetwork(props, ref) {
  const { graph, focusId, onFocus, shown, traceLevel, tracedEdge, step, allEvidence, labels, onZoom } = props;
  const host = useRef(null), canvas = useRef(null), engine = useRef(null), latest = useRef(props);
  const [hovered, setHovered] = useState(null);
  latest.current = props;
  const signature = graph.nodes.map(node => node.id).join('|') + ':' + graph.edges.map(edge => edge.id).join('|');
  useImperativeHandle(ref, () => ({
    zoom: factor => engine.current?.zoom(factor),
    fit: () => engine.current?.fit(),
    locate: id => engine.current?.locate(id),
  }), []);

  useEffect(() => {
    const element = canvas.current, container = host.current;
    const context = element.getContext('2d');
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let width = 1, height = 1, frame = 0, hoverId = null, gesture = null, disposed = false;
    let data = { nodes: [], links: [], byId: new Map() }, simulation;
    let camera = { x: 0, y: 0, k: 1 }, autoFit = true, theme;
    const pointers = new Map();
    const readTheme = () => {
      const css = getComputedStyle(container);
      theme = Object.fromEntries(Object.entries({ clean: '--ok', untrusted: '--warn', secret: '--bad', bait: '--bait', text: '--text-primary', secondary: '--text-secondary', background: '--network-bg', trace: '--accent' }).map(([name, token]) => [name, css.getPropertyValue(token).trim()]));
    };
    const publishZoom = () => latest.current.onZoom(camera.k);
    const fit = () => { camera = fitNetwork(data.nodes, width, height); autoFit = true; publishZoom(); paint(); };
    const activeNodes = () => data.nodes.filter(node => (latest.current.graph.byId.get(node.id)?.order ?? Infinity) < latest.current.shown);
    function draw() {
      frame = 0;
      if (disposed) return;
      const options = latest.current, model = options.graph;
      context.clearRect(0, 0, width, height);
      const visible = new Set(activeNodes().map(node => node.id));
      const active = hoverId || options.focusId;
      const neighbors = new Set(active ? [active] : []);
      data.links.forEach(link => { if (link.from === active) neighbors.add(link.to); if (link.to === active) neighbors.add(link.from); });
      options.traceLevel.forEach((level, id) => { if (level <= options.step) neighbors.add(id); });
      for (const link of data.links) {
        if (!visible.has(link.from) || !visible.has(link.to)) continue;
        const target = model.byId.get(link.to), source = model.byId.get(link.from);
        const level = options.tracedEdge.get(link.id), lit = level !== undefined && level <= options.step;
        if (!options.allEvidence && link.kind === 'evidence' && target.decision === 'allow' && !lit) continue;
        const near = link.from === active || link.to === active;
        const from = screenPoint(link.source, camera), to = screenPoint(link.target, camera);
        context.globalAlpha = lit ? 0.95 : active ? near ? 0.65 : 0.065 : link.kind === 'evidence' ? 0.21 : 0.35;
        context.strokeStyle = lit ? theme.trace : theme[colorKey(source)];
        context.lineWidth = lit ? 1.6 : near ? 1 : 0.65;
        context.setLineDash(link.kind === 'evidence' && (near || lit) ? [3, 4] : []);
        context.beginPath(); context.moveTo(from.x, from.y); context.lineTo(to.x, to.y); context.stroke();
        if (near || lit) {
          const angle = Math.atan2(to.y - from.y, to.x - from.x), radius = Math.max(2, nodeRadius(link.target) * camera.k) + 3;
          const x = to.x - Math.cos(angle) * radius, y = to.y - Math.sin(angle) * radius;
          context.setLineDash([]); context.beginPath();
          context.moveTo(x - Math.cos(angle - 0.5) * 5, y - Math.sin(angle - 0.5) * 5);
          context.lineTo(x, y); context.lineTo(x - Math.cos(angle + 0.5) * 5, y - Math.sin(angle + 0.5) * 5); context.stroke();
        }
      }
      context.setLineDash([]);
      const labelBoxes = [];
      for (const particle of data.nodes) {
        if (!visible.has(particle.id)) continue;
        const node = model.byId.get(particle.id), point = screenPoint(particle, camera);
        if (point.x < -100 || point.y < -40 || point.x > width + 100 || point.y > height + 40) continue;
        const selected = particle.id === options.focusId, hovered = particle.id === hoverId;
        const lit = options.traceLevel.has(node.id) && options.traceLevel.get(node.id) <= options.step;
        // A block/stop decision always wears a ring so it stands out among source dots.
        const blocked = node.type === 'decision' && node.decision && node.decision !== 'allow';
        const radius = Math.max(1.5, Math.min(14, nodeRadius(particle) * camera.k));
        context.globalAlpha = active && !neighbors.has(node.id) ? 0.22 : 1;
        context.fillStyle = theme[colorKey(node)];
        context.beginPath(); context.arc(point.x, point.y, radius, 0, Math.PI * 2); context.fill();
        if (selected || hovered || lit || blocked) {
          context.strokeStyle = lit ? theme.trace : theme[colorKey(node)]; context.lineWidth = selected || blocked ? 1.5 : 1;
          context.beginPath(); context.arc(point.x, point.y, radius + 4, 0, Math.PI * 2); context.stroke();
        }
        if (selected || hovered || (options.labels && (!active || neighbors.has(node.id)))) {
          const label = node.label.length > 32 ? node.label.slice(0, 31) + '…' : node.label;
          context.font = '11px "Geist Variable", system-ui, sans-serif';
          const textWidth = context.measureText(label).width, x = point.x + radius + 8, y = point.y + 4;
          const box = { x, y: y - 12, w: textWidth + 6, h: 17 };
          const overlaps = labelBoxes.some(other => box.x < other.x + other.w && box.x + box.w > other.x && box.y < other.y + other.h && box.y + box.h > other.y);
          if (selected || hovered || !overlaps) {
            labelBoxes.push(box); context.globalAlpha = 0.94; context.fillStyle = theme.background;
            context.fillRect(x - 3, y - 12, textWidth + 6, 17);
            context.globalAlpha = 1; context.fillStyle = selected || hovered ? theme.text : theme.secondary;
            context.fillText(label, x, y);
          }
        }
      }
      context.globalAlpha = 1;
    }
    function paint() { if (!frame && !disposed) frame = requestAnimationFrame(draw); }
    const point = event => { const rect = element.getBoundingClientRect(); return { x: event.clientX - rect.left, y: event.clientY - rect.top }; };
    const setHover = id => {
      if (hoverId === id) return;
      hoverId = id; setHovered(id); element.style.cursor = id ? 'pointer' : 'grab'; paint();
    };
    const zoom = (factor, origin = { x: width / 2, y: height / 2 }) => { camera = zoomAt(camera, origin, factor); autoFit = false; publishZoom(); paint(); };
    const locate = id => {
      const node = data.byId.get(id);
      if (!node) return;
      camera = { k: Math.max(camera.k, 1.5), x: 0, y: 0 };
      camera.x = width / 2 - node.x * camera.k; camera.y = height / 2 - node.y * camera.k;
      autoFit = false; publishZoom(); paint();
    };
    const down = event => {
      if (event.button !== 0) return;
      const p = point(event); pointers.set(event.pointerId, p); element.setPointerCapture(event.pointerId);
      if (pointers.size === 1) {
        const node = pickNode(activeNodes(), p, camera);
        gesture = { start: p, last: p, node, moved: false };
        if (node) { node.fx = node.x; node.fy = node.y; }
      } else {
        if (gesture?.node) { gesture.node.fx = null; gesture.node.fy = null; }
        gesture = { moved: true };
      }
      element.style.cursor = 'grabbing';
    };
    const move = event => {
      const p = point(event);
      if (!pointers.has(event.pointerId)) { setHover(pickNode(activeNodes(), p, camera)?.id || null); return; }
      const previous = [...pointers.values()]; pointers.set(event.pointerId, p);
      if (pointers.size > 1) {
        const next = [...pointers.values()];
        const center = points => ({ x: (points[0].x + points[1].x) / 2, y: (points[0].y + points[1].y) / 2 });
        const before = center(previous), after = center(next);
        const distance = points => Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y);
        camera.x += after.x - before.x; camera.y += after.y - before.y;
        zoom(distance(next) / Math.max(1, distance(previous)), after); return;
      }
      if (!gesture?.last) return;
      if (Math.hypot(p.x - gesture.start.x, p.y - gesture.start.y) > 4) gesture.moved = true;
      if (!gesture.moved) return;
      autoFit = false;
      if (gesture.node) {
        const world = worldPoint(p, camera);
        Object.assign(gesture.node, { fx: world.x, fy: world.y, x: world.x, y: world.y });
        if (!reduced) simulation.alphaTarget(0.06).restart();
      } else { camera.x += p.x - gesture.last.x; camera.y += p.y - gesture.last.y; }
      gesture.last = p; paint();
    };
    const up = event => {
      pointers.delete(event.pointerId);
      if (gesture?.node) { gesture.node.fx = null; gesture.node.fy = null; }
      if (!gesture?.moved && event.type !== 'pointercancel') latest.current.onFocus(gesture?.node?.id || null);
      simulation?.alphaTarget(0); gesture = pointers.size ? { moved: true } : null;
      element.style.cursor = 'grab'; paint();
    };
    const wheel = event => { event.preventDefault(); zoom(Math.exp(-Math.max(-100, Math.min(100, event.deltaY)) * 0.004), point(event)); };
    const keydown = event => {
      const nodes = activeNodes();
      if (event.key === '+' || event.key === '=') zoom(1.25);
      else if (event.key === '-') zoom(0.8);
      else if (event.key === '0' || event.key === 'Home') fit();
      else if (event.key === 'Escape') { latest.current.onFocus(null); setHover(null); }
      else if (event.key.startsWith('Arrow')) {
        const index = nodes.findIndex(node => node.id === (hoverId || latest.current.focusId));
        const direction = event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1;
        const node = nodes[(index + direction + nodes.length) % nodes.length];
        if (node) { setHover(node.id); locate(node.id); }
      } else if ((event.key === 'Enter' || event.key === ' ') && hoverId) latest.current.onFocus(hoverId);
      else return;
      event.preventDefault();
    };
    const leave = () => { if (!pointers.size) setHover(null); };
    const resize = () => {
      const rect = container.getBoundingClientRect(), ratio = Math.min(window.devicePixelRatio || 1, 2);
      const oldWidth = width, oldHeight = height; width = rect.width; height = rect.height;
      element.width = Math.round(width * ratio); element.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      if (autoFit) fit(); else { camera.x += (width - oldWidth) / 2; camera.y += (height - oldHeight) / 2; paint(); }
    };
    engine.current = {
      zoom, fit, locate, paint,
      update(model) {
        simulation?.stop();
        data = networkData(model, data.byId); simulation = networkSimulation(data);
        // Settle the initial shape before fitting. Subsequent live growth preserves positions.
        simulation.tick(data.nodes.length > 400 ? 45 : 90);
        if (autoFit) fit();
        simulation.on('tick', () => { if (autoFit) { camera = fitNetwork(data.nodes, width, height); publishZoom(); } paint(); });
        if (!reduced) simulation.restart();
        paint();
      },
    };
    readTheme();
    const observer = new ResizeObserver(resize); observer.observe(container);
    const themes = new MutationObserver(() => { readTheme(); paint(); }); themes.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    const events = { pointerdown: down, pointermove: move, pointerup: up, pointercancel: up, pointerleave: leave, keydown, wheel };
    Object.entries(events).forEach(([name, handler]) => element.addEventListener(name, handler, { passive: false }));
    resize();
    return () => {
      disposed = true; simulation?.stop(); cancelAnimationFrame(frame); observer.disconnect(); themes.disconnect(); engine.current = null;
      Object.entries(events).forEach(([name, handler]) => element.removeEventListener(name, handler));
    };
  }, []);

  useEffect(() => { engine.current?.update(graph); }, [signature]); // Preserve layout on polling.
  useEffect(() => { engine.current?.paint(); }, [graph, focusId, shown, traceLevel, tracedEdge, step, allEvidence, labels]);
  const node = graph.byId.get(hovered), info = node ? nodePresentation(node) : null;
  return <div className="networkViewport" ref={host}>
    <canvas ref={canvas} tabIndex={0} role="group" aria-label={`Interactive provenance network, ${graph.nodes.length} nodes. Drag to pan or move nodes. Scroll to zoom. Arrow keys browse nodes, Enter selects, zero fits graph.`} />
    <div className="networkInstructions">Drag to pan <span>·</span> Pinch or scroll to zoom</div>
    {info && <div className="networkTooltip" role="status">
      <strong>{info.title}</strong><code>{info.resource}</code><span>{info.caption}</span><small>{info.detail}</small>
    </div>}
  </div>;
});
