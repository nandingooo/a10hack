import React, { useMemo, useState } from 'react';
import AgentGraph from './AgentGraph.jsx';
import { canStop, eventTime, runStatus } from './managedGateway.js';
import { isRunning, relativeTime, useLiveAgents } from './liveAgents.js';
import { buildGraph } from './provenanceGraph.js';
import './ide.css';
import './agents.css';

const FEED_TYPES = new Set(['decision', 'enforcement', 'result', 'session', 'kill', 'artifact_move']);
const EMPTY = [];

function AgentRow({ title, subtitle, status, live, denials, selected, onSelect }) {
  return <li><button className={'agentRow' + (selected ? ' selected' : '')} onClick={onSelect} aria-pressed={selected}>
    <i className={'dot ' + (live ? 'running' : status === 'KILLED' || status === 'STOPPED' ? 'finished' : 'preview')} aria-hidden="true" />
    <span><b>{title}</b><small>{subtitle}</small></span>
    {denials > 0 && <em title="Blocked or stopped actions">{denials}</em>}
  </button></li>;
}

function FeedItem({ event, focusable, focused, onFocus }) {
  const verdict = event.decision?.toUpperCase() || (event.type === 'enforcement' ? 'ENFORCED' : null);
  const what = [event.op, event.target].filter(Boolean).join(' · ') || event.status || event.type;
  const body = <>
    <time>#{event.seq} · {eventTime(event)}</time>
    <div><b className={'verdict ' + (verdict || 'INFO')}>{verdict || event.type}</b><strong>{what}</strong></div>
    {event.rule && <code>{event.rule}</code>}
    {event.execution_status && <p>execution {event.execution_status} · exposure {event.exposure_status}</p>}
  </>;
  return <li className={'actionItem' + (focused ? ' focused' : '')}>
    {focusable ? <button className="feedButton" onClick={onFocus} title="Trace this decision in the graph">{body}</button> : body}
  </li>;
}

/** Explicit choice wins; otherwise prefer a running live agent, then the newest managed run. */
function defaultSelection(liveAgents, runs) {
  const running = liveAgents.find(agent => isRunning(agent));
  if (running) return { source: 'live', id: running.session_id };
  if (runs.length) return { source: 'managed', id: runs[0].id };
  if (liveAgents.length) return { source: 'live', id: liveAgents[0].session_id };
  return null;
}

export default function AgentsPage({ managed, signedIn, setProfile }) {
  const live = useLiveAgents(signedIn, setProfile);
  const [choice, setChoice] = useState(null);
  const [focusId, setFocusId] = useState(null);
  const liveAgents = live.state?.agents || EMPTY;
  const runs = managed.state?.runs || EMPTY;
  const selection = choice || defaultSelection(liveAgents, runs);

  const choose = next => {
    setChoice(next);
    setFocusId(null);
    if (next.source === 'live') live.select(next.id);
    else managed.select(next.id);
  };

  const isLive = selection?.source === 'live';
  const liveReady = Boolean(isLive && live.state?.agent) && live.state.agent.session_id === selection.id;
  const managedReady = Boolean(selection && !isLive && managed.state?.run) && managed.state.run.id === selection.id;
  const events = (liveReady ? live.state.events : managedReady ? managed.state.events : null) || EMPTY;
  const entries = (liveReady ? live.state.entries : managedReady ? managed.state.entries : null) || EMPTY;
  const graph = useMemo(() => buildGraph(entries, events), [entries, events]);
  const feed = events.filter(event => FEED_TYPES.has(event.type)).slice().reverse();

  const gateway = live.state?.gateway;
  const selectedLive = liveAgents.find(agent => agent.session_id === selection?.id);
  const stoppable = isLive ? Boolean(selectedLive) && selectedLive.status !== 'KILLED' : canStop(managed.state?.run);
  const stop = () => (isLive ? live.stop(selection.id) : managed.command('stop'));
  const message = live.error || managed.error;

  if (!signedIn) {
    return <section className="ide agentsPage"><div className="emptySession"><a href="#signin">Sign in with the workspace code</a> to see agents.</div></section>;
  }

  const guardLabel = gateway ? (gateway.ok ? 'connected' : 'offline') : '…';
  const liveHint = gateway?.ok ? 'No hook sessions yet. Start Claude Code with the TrustAgent hook installed.'
    : 'Start the guard: python trust_agent/gateway/app/service.py';

  return <section className="ide agentsPage" aria-label="Agents, activity and provenance graph">
    <header className="ideBar">
      <h1>Agents</h1>
      <span className="runtime" title={gateway?.error || ''}>
        <i className={'dot ' + (gateway?.ok ? 'running' : 'unavailable')} aria-hidden="true" /> Hook guard {guardLabel} · {gateway?.url || ''}
      </span>
      <button disabled={!stoppable} onClick={stop}>■ Stop agent</button>
    </header>
    {message && <div className="notice alert" role="alert">{message}</div>}
    <div className="agentsGrid">
      <aside className="agentList" aria-label="Agents">
        <h2>Claude Code sessions</h2>
        {liveAgents.length ? <ul>{liveAgents.map(agent => {
          const state = agent.status === 'KILLED' ? 'stopped' : isRunning(agent) ? 'running' : 'idle';
          return <AgentRow key={agent.session_id} title={agent.session_id.slice(0, 18)} live={isRunning(agent)}
            status={agent.status} denials={agent.denials}
            subtitle={`${state} · ${agent.decisions ?? '?'} decisions · ${relativeTime(agent.last_ts)}`}
            selected={isLive && selection.id === agent.session_id}
            onSelect={() => choose({ source: 'live', id: agent.session_id })} />;
        })}</ul> : <p className="muted">{liveHint}</p>}
        <h2>Managed sandbox runs</h2>
        {runs.length ? <ul>{runs.map(run => <AgentRow key={run.id} title={run.scenarioTitle}
          live={run.status === 'RUNNING'} status={run.status} subtitle={`${run.id.slice(0, 8)} · ${runStatus(run.status)}`}
          selected={!isLive && selection?.id === run.id} onSelect={() => choose({ source: 'managed', id: run.id })} />)}</ul>
          : <p className="muted">No managed runs. Launch one from the Console.</p>}
      </aside>
      <div className="graphPane">
        <div className="paneTitle"><span>Provenance graph</span><small>{selection ? selection.id.slice(0, 18) : 'no agent selected'}</small></div>
        <AgentGraph key={selection ? selection.source + selection.id : 'none'} graph={graph} focusId={focusId} onFocus={setFocusId} />
      </div>
      <aside className="activityFeed" aria-label="Agent activity">
        <div className="paneTitle"><span>Activity</span><small>{feed.length} events</small></div>
        {feed.length ? <ol className="actionList">{feed.map(event => {
          const nodeId = 'decision:' + event.seq;
          const focusable = event.type === 'decision' && graph.byId.has(nodeId);
          return <FeedItem key={event.seq} event={event} focusable={focusable} focused={focusId === nodeId}
            onFocus={() => setFocusId(nodeId)} />;
        })}</ol> : <div className="emptySession">Waiting for agent activity…</div>}
      </aside>
    </div>
  </section>;
}
