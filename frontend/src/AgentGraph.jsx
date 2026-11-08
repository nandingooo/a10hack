import React, { useEffect, useMemo, useRef, useState } from 'react';
import { nodePresentation, taint, traceBack } from './provenanceGraph.js';
import ForceNetwork from './ForceNetwork.jsx';

const BUILD_STEP_MS = 320;
const TRACE_STEP_MS = 750;
const NO_TRACE = { levels: [], edges: [], tainted: [] };

function GraphIcon({ name }) {
  const paths = {
    replay: 'M4 8a8 8 0 1 1-1 8M4 3v5h5',
    trace: 'M5 6h5v5M10 6l-6 6m6 0h4v6m0-6 6 6',
    minus: 'M5 12h14', plus: 'M5 12h14M12 5v14',
    fit: 'M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5',
    search: 'M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
    close: 'M6 6l12 12M6 18 18 6',
  };
  return <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>;
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
  if (!focus) return <div className="traceHint"><strong>Follow the evidence</strong><p>Select a node to inspect its tags and trace the recorded context behind a decision.</p><small>Links include recorded provenance and inferred context.</small></div>;
  const done = step >= trace.levels.length - 1;
  const names = ids => ids.map(id => graph.byId.get(id)?.label).join(', ');
  const verdict = focus.decision?.toUpperCase();
  const info = nodePresentation(focus);
  return <div className="traceSummary" aria-live="polite">
    <div className="inspectorHeading"><strong>{focus.label}</strong><span>{focus.type === 'decision' ? 'Decision' : 'Resource'}</span></div>
    <dl className="graphNodeDetails">
      <dt>Resource</dt><dd><code>{info.resource}</code></dd>
      <dt>{focus.type === 'decision' ? 'Verdict' : 'Tags'}</dt><dd>{focus.type === 'decision' ? info.caption : info.tags.join(' · ')}</dd>
      <dt>{focus.type === 'decision' ? 'Context' : 'Observation'}</dt><dd>{info.detail}</dd>
    </dl>
    {focus.reason && <p className="decisionReason">{focus.reason}</p>}
    {trace.levels.length > 1 && <details className="traceHops"><summary>Recorded context · {Math.max(0, trace.levels.length - 1)} hops</summary><ol>{trace.levels.slice(1, step + 1).map((level, index) => <li key={index}><b>Hop {index + 1}</b> {names(level)}</li>)}</ol></details>}
    {done && <p>
      {focus.type === 'decision' && <><b className={'verdict ' + verdict}>{verdict}</b> <code>{focus.rule}</code> · </>}
      {trace.tainted.length
        ? <>reached {trace.tainted.length} risky source{trace.tainted.length > 1 ? 's' : ''}: {trace.tainted.map(id => {
          const node = graph.byId.get(id);
          return <span key={id} className={'taintChip taint-' + taint(node)}>{node.label} · {taint(node)}</span>;
        })}</>
        : focus.parents.length ? 'No risky labels among recorded ancestors.' : 'No recorded parent links.'}
    </p>}
  </div>;
}

export default function AgentGraph({ graph, focusId, onFocus }) {
  const [replayRun, setReplayRun] = useState(0);
  const [traceRun, setTraceRun] = useState(0);
  const [allEvidence, setAllEvidence] = useState(true);
  const [zoom, setZoom] = useState(100);
  const [labels, setLabels] = useState(false);
  const [query, setQuery] = useState('');
  const network = useRef(null);
  const shown = useBuildReplay(graph.nodes.length, replayRun);
  // Re-trace only when the focus or the graph's shape changes, not on every 1 s poll.
  const shape = graph.nodes.map(node => node.id).join('|') + ':' + graph.edges.map(edge => edge.id).join('|');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const trace = useMemo(() => (focusId ? traceBack(graph, focusId) : NO_TRACE), [focusId, shape]);
  const step = useTraceStep(trace, traceRun);
  const traceLevel = new Map(trace.levels.flatMap((ids, level) => ids.map(id => [id, level])));
  const tracedEdge = new Map(trace.edges.map(edge => [edge.id, edge.level]));
  const focus = focusId ? graph.byId.get(focusId) : null;
  const matches = query.trim() ? graph.nodes.filter(node => [node.label, node.target, node.trust, node.sensitivity, node.rule, node.decision, node.bait ? 'bait' : ''].filter(Boolean).join(' ').toLowerCase().includes(query.trim().toLowerCase())) : [];
  const select = id => { onFocus(id); network.current?.locate(id); setQuery(''); };

  return <div className="agentGraph">
    <div className="graphTools">
      <div className="networkSearch">
        <GraphIcon name="search" /><input type="search" aria-label="Find a file, tag or decision" placeholder="Find a file, tag or decision…" value={query} onChange={event => setQuery(event.target.value)} onKeyDown={event => { if (event.key === 'Escape') setQuery(''); if (event.key === 'Enter' && matches[0]) select(matches[0].id); }} />
        {query.trim() && <div className="networkResults" aria-label="Matching nodes">
          {matches.length ? <><small>{matches.length} matching nodes{matches.length > 20 ? ' · first 20 shown' : ''}</small>{matches.slice(0, 20).map(node => <button key={node.id} onClick={() => select(node.id)}><i className={'nodeSwatch ' + (node.type === 'decision' ? 'decision ' + node.decision : 'taint-' + taint(node))} /><span><strong>{node.label}</strong><small>{node.target}</small></span><em>{node.type === 'decision' ? node.decision : taint(node)}</em></button>)}</> : <p>No matching nodes.</p>}
        </div>}
      </div>
      <div className="graphReplayTools">
        <button disabled={!graph.nodes.length} onClick={() => setReplayRun(run => run + 1)} title="Replay graph growth"><GraphIcon name="replay" />Replay</button>
        <button disabled={!focus} onClick={() => setTraceRun(run => run + 1)} title="Replay the backward evidence trace"><GraphIcon name="trace" />Trace</button>
      </div>
    </div>
    <div className="graphLegend" aria-hidden="true">
      <span className="taint-clean">trusted</span><span className="taint-untrusted">untrusted</span>
      <span className="taint-secret">secret</span><span className="taint-bait">bait</span>
      <span className="decision allow">allow</span><span className="decision block">block</span><span className="decision stop">stop</span>
      <span className="graphStats">{graph.nodes.length} nodes · {graph.edges.length} links</span>
    </div>
    <div className="networkStage">
      {graph.nodes.length === 0 ? <div className="graphEmpty"><GraphIcon name="trace" /><strong>Waiting for agent activity</strong><p>File reads and decisions will build the network here.</p></div>
        : <ForceNetwork ref={network} graph={graph} focusId={focusId} onFocus={onFocus} shown={shown} traceLevel={traceLevel} tracedEdge={tracedEdge} step={step} allEvidence={allEvidence} labels={labels} onZoom={value => setZoom(Math.round(value * 100))} />}
      <div className="networkOptions">
        <label><input type="checkbox" checked={labels} onChange={event => setLabels(event.target.checked)} />Labels</label>
        <label title="Include recorded context links for allowed decisions; these can include conservative inferences."><input type="checkbox" checked={allEvidence} onChange={event => setAllEvidence(event.target.checked)} />All context</label>
      </div>
      <div className="networkNavigation" role="group" aria-label="Graph navigation">
        <button disabled={!graph.nodes.length || zoom <= 12} onClick={() => network.current?.zoom(0.8)} aria-label="Zoom out graph"><GraphIcon name="minus" /></button>
        <output aria-label="Graph zoom">{zoom}%</output>
        <button disabled={!graph.nodes.length || zoom >= 800} onClick={() => network.current?.zoom(1.25)} aria-label="Zoom in graph"><GraphIcon name="plus" /></button>
        <button disabled={!graph.nodes.length} onClick={() => network.current?.fit()} aria-label="Fit graph" title="Fit graph (0)"><GraphIcon name="fit" /></button>
      </div>
    </div>
    {focus && <button className="clearGraphSelection" onClick={() => onFocus(null)}><GraphIcon name="close" />Clear selection</button>}
    <TraceSummary graph={graph} trace={trace} step={step} focus={focus} />
  </div>;
}
