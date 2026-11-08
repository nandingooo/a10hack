import React, { useEffect, useMemo, useState } from 'react';
import { NODE_HEIGHT, NODE_WIDTH, taint, traceBack } from './provenanceGraph.js';

const BUILD_STEP_MS = 320;
const TRACE_STEP_MS = 750;
const NO_TRACE = { levels: [], edges: [], tainted: [] };
const NODE_KIND = { source: 'read', secret: 'secret read', action: 'write', decision: 'decision' };

function edgePath(from, to) {
  const x1 = from.x + NODE_WIDTH, y1 = from.y + NODE_HEIGHT / 2;
  const x2 = to.x, y2 = to.y + NODE_HEIGHT / 2;
  const bend = Math.max(40, (x2 - x1) / 2);
  return `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`;
}

function nodeClass(node, traceLevel, step) {
  const classes = ['gnode', node.type === 'decision' ? 'decision ' + node.decision : 'taint-' + taint(node)];
  const level = traceLevel.get(node.id);
  if (level !== undefined && level <= step) classes.push(level === step ? 'frontier' : 'traced');
  return classes.join(' ');
}

function GraphNode({ node, className, onSelect }) {
  const caption = node.type === 'decision'
    ? `${(node.decision || '').toUpperCase()} · ${node.rule || ''}`
    : `${NODE_KIND[node.type]} · ${taint(node)}`;
  const label = node.label.length > 22 ? node.label.slice(0, 21) + '…' : node.label;
  return <g className={className} transform={`translate(${node.x},${node.y})`}
    onClick={() => onSelect(node.id)} role="button" tabIndex={0}
    onKeyDown={event => { if (event.key === 'Enter') onSelect(node.id); }}>
    <title>{[node.target, node.rule, node.reason, node.basis].filter(Boolean).join('\n')}</title>
    <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="8" />
    <text x="10" y="16" className="gLabel">{label}</text>
    <text x="10" y="31" className="gCaption">{caption}</text>
  </g>;
}

/** Reveal nodes one by one (in creation order) each time `run` increments; Infinity = show all. */
function useBuildReplay(total, run) {
  const [shown, setShown] = useState(Infinity);
  useEffect(() => {
    if (!run) return undefined;
    setShown(0);
    const timer = setInterval(() => setShown(count => {
      if (count >= total) { clearInterval(timer); return Infinity; }
      return count + 1;
    }), BUILD_STEP_MS);
    return () => clearInterval(timer);
    // `total` intentionally omitted: live growth during a replay must not restart it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run]);
  return shown;
}

/** Advance the BFS frontier one level per tick each time the trace or `run` changes. */
function useTraceStep(trace, run) {
  const [step, setStep] = useState(-1);
  useEffect(() => {
    if (!trace.levels.length) { setStep(-1); return undefined; }
    setStep(0);
    const timer = setInterval(() => setStep(current => {
      if (current >= trace.levels.length - 1) { clearInterval(timer); return current; }
      return current + 1;
    }), TRACE_STEP_MS);
    return () => clearInterval(timer);
  }, [trace, run]);
  return step;
}

function TraceSummary({ graph, trace, step, focus }) {
  if (!focus) return <p className="traceHint">Click a decision (or any node) to trace the context that could have reached it.</p>;
  const done = step >= trace.levels.length - 1;
  const names = ids => ids.map(id => graph.byId.get(id)?.label).join(', ');
  const verdict = focus.decision?.toUpperCase();
  return <div className="traceSummary" aria-live="polite">
    <strong>Tracing back from {focus.label}</strong>
    <ol>{trace.levels.slice(1, step + 1).map((level, index) => <li key={index}><b>Hop {index + 1}</b> {names(level)}</li>)}</ol>
    {done && <p>
      {focus.type === 'decision' && <><b className={'verdict ' + verdict}>{verdict}</b> <code>{focus.rule}</code> · </>}
      {trace.tainted.length
        ? <>reached {trace.tainted.length} risky source{trace.tainted.length > 1 ? 's' : ''}: {trace.tainted.map(id => {
          const node = graph.byId.get(id);
          return <span key={id} className={'taintChip taint-' + taint(node)}>{node.label} · {taint(node)}</span>;
        })}</>
        : 'no untrusted or secret context reached this node.'}
    </p>}
  </div>;
}

export default function AgentGraph({ graph, focusId, onFocus }) {
  const [replayRun, setReplayRun] = useState(0);
  const [traceRun, setTraceRun] = useState(0);
  const [allEvidence, setAllEvidence] = useState(false);
  const shown = useBuildReplay(graph.nodes.length, replayRun);
  // Re-trace only when the focus or the graph's shape changes, not on every 1 s poll.
  const shape = graph.nodes.length + ':' + graph.edges.length;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const trace = useMemo(() => (focusId ? traceBack(graph, focusId) : NO_TRACE), [focusId, shape]);
  const step = useTraceStep(trace, traceRun);
  const traceLevel = new Map(trace.levels.flatMap((ids, level) => ids.map(id => [id, level])));
  const tracedEdge = new Map(trace.edges.map(edge => [edge.id, edge.level]));
  const visible = node => node.order < shown;
  const focus = focusId ? graph.byId.get(focusId) : null;

  const edges = graph.edges.filter(edge => {
    const from = graph.byId.get(edge.from), to = graph.byId.get(edge.to);
    if (!visible(from) || !visible(to)) return false;
    if (tracedEdge.has(edge.id)) return true;
    // A decision's evidence is the whole session context (conservative join); drawing every
    // such edge for allowed actions hides the signal, so only denials show them by default.
    return allEvidence || edge.kind !== 'evidence' || to.decision !== 'allow';
  });

  return <div className="agentGraph">
    <div className="graphTools">
      <button onClick={() => setReplayRun(run => run + 1)}>▶ Replay tree build</button>
      <button disabled={!focus} onClick={() => setTraceRun(run => run + 1)}>↺ Replay traversal</button>
      <label><input type="checkbox" checked={allEvidence} onChange={event => setAllEvidence(event.target.checked)} /> All evidence edges</label>
      <span className="graphStats">{graph.nodes.length} nodes · {graph.edges.length} edges</span>
    </div>
    <div className="graphLegend" aria-hidden="true">
      <span className="taint-clean">trusted</span><span className="taint-untrusted">untrusted</span>
      <span className="taint-secret">secret</span><span className="taint-bait">bait</span>
      <span className="decision allow">allow</span><span className="decision block">block</span><span className="decision stop">stop</span>
    </div>
    {graph.nodes.length === 0 ? <div className="emptySession">No provenance yet. Reads and actions appear here as the agent works.</div>
      : <div className="graphCanvas">
        <svg width={graph.width} height={graph.height} role="img" aria-label="Provenance graph">
          <defs><marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" /></marker></defs>
          {edges.map(edge => {
            const level = tracedEdge.get(edge.id);
            const lit = level !== undefined && level <= step;
            return <path key={edge.id} d={edgePath(graph.byId.get(edge.from), graph.byId.get(edge.to))}
              pathLength="1" markerEnd="url(#arrow)" className={'gedge ' + edge.kind + (lit ? ' traced' : '')} />;
          })}
          {graph.nodes.filter(visible).map(node =>
            <GraphNode key={node.id} node={node} className={nodeClass(node, traceLevel, step)} onSelect={onFocus} />)}
        </svg>
      </div>}
    <TraceSummary graph={graph} trace={trace} step={step} focus={focus} />
  </div>;
}
