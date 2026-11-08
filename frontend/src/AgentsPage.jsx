import React, { useEffect, useMemo, useState } from 'react';
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
    <span><b title={title}>{title}</b><small>{subtitle}</small></span>
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
  return <li className={'actionItem event-' + event.type + (focused ? ' focused' : '')}>
    {focusable ? <button className="feedButton" onClick={onFocus} title="Trace this decision in the graph">{body}</button> : body}
  </li>;
}

/** Inputs contain running agents only; prefer a hook session, then a sandbox. */
function defaultSelection(liveAgents, runs) {
  if (liveAgents.length) return { source: 'live', id: liveAgents[0].session_id };
  if (runs.length) return { source: 'managed', id: runs[0].id };
  return null;
}

export default function AgentsPage({ managed, signedIn, setProfile }) {
  const live = useLiveAgents(signedIn, setProfile);
  const [choice, setChoice] = useState(null);
  const [focusId, setFocusId] = useState(null);
  const [feedFilter, setFeedFilter] = useState('all');
  // Keep every session that hasn't been killed — an idle session must stay listed
  // and selectable (its graph/activity shouldn't vanish after a lull). `isRunning`
  // is used only for the live "dot" / running-vs-idle label below.
  const liveAgents = (live.state?.agents || EMPTY).filter(agent => agent.status !== 'KILLED');
  const runs = (managed.state?.runs || EMPTY).filter(run => run.status === 'RUNNING');
  const choiceVisible = choice && (choice.source === 'live'
    ? liveAgents.some(agent => agent.session_id === choice.id)
    : runs.some(run => run.id === choice.id));
  const selection = choiceVisible ? choice : defaultSelection(liveAgents, runs);

  useEffect(() => {
    if (choice && !choiceVisible) setChoice(null);
  }, [choice, choiceVisible]);

  useEffect(() => {
    setFocusId(null);
  }, [selection?.source, selection?.id]);

  useEffect(() => {
    const liveId = selection?.source === 'live' ? selection.id : '';
    const managedId = selection?.source === 'managed' ? selection.id : '';
    if (live.session !== liveId) live.select(liveId);
    if (managed.session !== managedId) managed.select(managedId);
  }, [selection?.source, selection?.id, live.session, live.select, managed.session, managed.select]);

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
  const filteredFeed = feed.filter(event => feedFilter === 'all' || (feedFilter === 'decisions' ? event.type === 'decision' : event.decision === 'block' || event.decision === 'stop' || event.type === 'kill'));

  const gateway = live.state?.gateway;
  const selectedLive = liveAgents.find(agent => agent.session_id === selection?.id);
  const stoppable = isLive ? Boolean(selectedLive) : managedReady && canStop(managed.state?.run);
  const stop = () => {
    if (!stoppable) return;
    return isLive ? live.stop(selection.id) : managed.command('stop');
  };
  const message = live.error || managed.error;

  if (!signedIn) {
    return <section className="ide agentsPage"><div className="emptySession"><a href="#signin">Sign in with the workspace code</a> to see agents.</div></section>;
  }

  const guardLabel = gateway ? (gateway.ok ? 'connected' : 'offline') : '…';
  const liveHint = gateway?.ok ? 'No running Claude Code sessions. Start Claude Code with the TrustAgent hook installed.'
    : 'Start the guard: python trust_agent/gateway/app/service.py';

  return <section className="ide agentsPage" aria-label="Agents, activity and provenance graph">
    <header className="ideBar">
      <h1>Agents</h1>
      <span className="runtime" title={gateway?.error || gateway?.url || ''}>
        <i className={'dot ' + (gateway?.ok ? 'running' : 'unavailable')} aria-hidden="true" /> Guard {guardLabel}
      </span>
      <button className="agentStop" disabled={!stoppable} onClick={stop}><svg viewBox="0 0 12 12" aria-hidden="true"><rect x="2" y="2" width="8" height="8" rx="1" /></svg>Stop agent</button>
    </header>
    {message && <div className="notice alert" role="alert">{message}</div>}
    <div className="agentsGrid">
      <aside className="agentList" aria-label="Agents">
        <h2>Claude Code <small>{liveAgents.length}</small></h2>
        {liveAgents.length ? <ul>{liveAgents.map(agent => {
          const state = agent.status === 'KILLED' ? 'stopped' : isRunning(agent) ? 'running' : 'idle';
          return <AgentRow key={agent.session_id} title={agent.session_id.slice(0, 18)} live={isRunning(agent)}
            status={agent.status} denials={agent.denials}
            subtitle={`${state} · ${agent.decisions ?? '?'} decisions · ${relativeTime(agent.last_ts)}`}
            selected={isLive && selection.id === agent.session_id}
            onSelect={() => choose({ source: 'live', id: agent.session_id })} />;
        })}</ul> : <p className="muted">{liveHint}</p>}
        <h2>Sandboxes <small>{runs.length}</small></h2>
        {runs.length ? <ul>{runs.map(run => <AgentRow key={run.id} title={run.scenarioTitle}
          live={run.status === 'RUNNING'} status={run.status} subtitle={`${run.id.slice(0, 8)} · ${runStatus(run.status)}`}
          selected={!isLive && selection?.id === run.id} onSelect={() => choose({ source: 'managed', id: run.id })} />)}</ul>
          : <p className="muted">No running sandbox agents. Launch one from the Console.</p>}
      </aside>
      <div className="graphPane">
        <div className="paneTitle"><span>Provenance graph</span><small>{selection ? selection.id.slice(0, 18) : 'no agent selected'}</small></div>
        <AgentGraph key={selection ? selection.source + selection.id : 'none'} graph={graph} focusId={focusId} onFocus={setFocusId} />
      </div>
      <aside className="activityFeed" aria-label="Agent activity">
        <div className="paneTitle"><span>Activity</span><small>{feed.length} events</small></div>
        <div className="activityFilters" role="group" aria-label="Filter activity">
          {[['all', 'All events'], ['decisions', 'Decisions'], ['blocked', 'Blocked']].map(([value, label]) => <button key={value} aria-pressed={feedFilter === value} onClick={() => setFeedFilter(value)}>{label}</button>)}
        </div>
        {filteredFeed.length ? <ol className="actionList">{filteredFeed.map(event => {
          const nodeId = 'decision:' + event.seq;
          const focusable = event.type === 'decision' && graph.byId.has(nodeId);
          return <FeedItem key={event.seq} event={event} focusable={focusable} focused={focusId === nodeId}
            onFocus={() => setFocusId(nodeId)} />;
        })}</ol> : <div className="emptySession">{feed.length ? 'No matching events.' : selection ? 'Waiting for agent activity…' : 'No running agents.'}</div>}
      </aside>
    </div>
  </section>;
}
