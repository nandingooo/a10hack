import React, { useState } from 'react';
import { canStop, eventTime, runStatus } from './managedGateway.js';
import './ide.css';

function AuditEvent({ event }) {
  const verdict = event.decision?.toUpperCase();
  const evidence = event.evidence || [];
  return <article className="actionItem">
    <time>#{event.seq} · {eventTime(event)}</time>
    <div>
      <b className={'verdict ' + (verdict || 'INFO')}>{verdict || event.type}</b>
      <strong>{[event.op, event.target].filter(Boolean).join(' · ') || event.status || event.tool_use_id}</strong>
    </div>
    {event.rule && <code>{event.rule}</code>}
    {event.reason && <p>{event.reason}</p>}
    {event.execution_status && <p>Execution {event.execution_status} · Exposure {event.exposure_status}</p>}
    {evidence.length > 0 && <details>
      <summary>Evidence ({evidence.length})</summary>
      <ul>{evidence.map((entry, index) => <li key={entry.id || index}>
        <strong>{entry.target}</strong>
        <code>{[entry.trust, entry.sensitivity, entry.basis].filter(Boolean).join(' · ')}</code>
      </li>)}</ul>
    </details>}
  </article>;
}

export default function ManagedConsole({ state, error, command, select, pending, session, signedIn }) {
  const [choice, setChoice] = useState('');
  const scenarios = state?.scenarios || [];
  const scenario = scenarios.find(item => item.id === choice) || scenarios[0];
  const run = state?.run;
  const message = error || run?.stopError || state?.startError;
  const changing = Boolean(session && run?.id !== session);
  const events = changing ? [] : state?.events || [];
  return <section className="ide managedConsole" aria-label="Managed agent console">
    <header className="ideBar">
      <h1>Agent console</h1><span className="runtime">Managed sandbox</span>
      <button className="runAgent" disabled={pending || state?.starting || (signedIn && !scenario)}
        onClick={() => command('start', scenario?.id)}>
        {state?.starting ? 'Starting rehearsal…' : '▶ Run rehearsal'}
      </button>
      <button disabled={pending || changing || !canStop(run)} onClick={() => command('stop')}>
        {run?.status === 'STOPPING' ? 'Stopping…' : '■ Stop run'}
      </button>
    </header>
    {message && <div className="notice alert" role="alert">{message}</div>}
    {!signedIn ? <div className="emptySession"><a href="#signin">Sign in with the workspace code</a></div>
      : <div className="managedAudit">
        {scenario && <div className="managedRehearsal">
          <label>Rehearsal scenario <select value={scenario.id} onChange={event => setChoice(event.target.value)}>
            {scenarios.map(item => <option key={item.id} value={item.id}>{item.title}</option>)}
          </select></label>
          <p>{scenario.description}</p>
        </div>}
        <div className="paneTitle managedSession">
          <label>Session <select aria-label="Session" value={session || run?.id || ''} onChange={event => select(event.target.value)}>
            {!state?.runs.length && <option value="">No managed sessions</option>}
            {state?.runs.map(item => <option key={item.id} value={item.id}>
              {item.scenarioTitle} · {item.id.slice(0, 8)} · {runStatus(item.status)}
            </option>)}
          </select></label>
          <span role="status">{changing ? 'Loading session…' : run ? runStatus(run.status) : state?.starting ? 'Launching…' : 'Waiting'}</span>
        </div>
        {events.length > 0 ? <div className="actionList managedActions" aria-label="Gateway audit events">
          {[...events].reverse().map(event => <AuditEvent event={event} key={event.seq} />)}
        </div> : <div className="emptySession">
          {state?.starting ? 'Preparing the managed sandbox. The first image build can take a few minutes.'
            : run ? 'Waiting for gateway audit events…' : 'Run the scripted rehearsal or launch a managed session from the CLI.'}
        </div>}
      </div>}
  </section>;
}
