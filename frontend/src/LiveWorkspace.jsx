import React, { useEffect, useState } from 'react';

import AgentIDE from './AgentIDE.jsx';
import ManagedConsole from './ManagedConsole.jsx';
import { MANAGED, canStop, previewState } from './managedGateway.js';

async function api(path, method = 'GET') {
  const response = await fetch('/api/' + path, { method, headers: { 'X-Airlock-Demo': '1' }, cache: 'no-store' });
  if (!response.ok) throw Error('Gateway unreachable');
  return response.json();
}

export function useGateway(enabled) {
  const [state, setState] = useState(null);
  const [error, setError] = useState('');
  async function command(action) {
    try { setState(await api(action, 'POST')); setError(''); }
    catch { setError('Gateway offline. Start python3 demo/gateway.py in the project folder.'); }
  }
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    let timer;
    async function refresh() {
      try {
        let snapshot = await api('state');
        if (!snapshot.id && active) snapshot = await api('start', 'POST');
        if (active) { setState(snapshot); setError(''); }
      } catch {
        if (active) setError('Gateway offline. Start python3 demo/gateway.py in the project folder.');
      }
      if (active) timer = setTimeout(refresh, 450);
    }
    refresh();
    return () => { active = false; clearTimeout(timer); };
  }, [enabled]);
  return { state, error, command };
}

const icon = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', viewBox: '0 0 24 24', 'aria-hidden': true };
const railLinks = [
  ['#live', 'Live agents', <path d="M6 3.5l12.5 7.2-5.6 1.7-2.3 5.6z" fill="currentColor" />],
  ['#console', 'Agent console', <><rect x="3" y="4.5" width="18" height="15" rx="3" /><path d="M7.5 9.5l3 2.5-3 2.5M12.5 15h4" /></>],
  ['#architecture', 'Architecture', <><path d="M12 3.5l8.5 4.7L12 13 3.5 8.2z" /><path d="M3.5 12.5L12 17.3l8.5-4.8" /></>],
  ['#faq', 'FAQ', <><circle cx="12" cy="12" r="8.5" /><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5M12 16.8h.01" /></>],
  ['#signin', 'Account', <><circle cx="12" cy="8.5" r="3.8" /><path d="M4.5 20c1.4-3.6 4.2-5.4 7.5-5.4s6.1 1.8 7.5 5.4" /></>],
];

function useElapsed(runId, running) {
  const [start, setStart] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { setStart(Date.now()); setNow(Date.now()); }, [runId]);
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [running]);
  const seconds = Math.max(0, Math.round((now - start) / 1000));
  return seconds < 60 ? seconds + 's' : Math.floor(seconds / 60) + 'm ' + String(seconds % 60).padStart(2, '0') + 's';
}

function useClock() {
  const format = () => new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const [time, setTime] = useState(format);
  useEffect(() => {
    const timer = setInterval(() => setTime(format()), 15000);
    return () => clearInterval(timer);
  }, []);
  return time;
}

function Wallpaper() {
  return <svg className="wallpaper" viewBox="0 0 1200 760" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
    <defs>
      <linearGradient id="wp-sky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor="#1b1325" /><stop offset=".42" stopColor="#6e3024" />
        <stop offset=".72" stopColor="#d9733c" /><stop offset="1" stopColor="#f5b06a" />
      </linearGradient>
      <radialGradient id="wp-sun" cx=".84" cy=".34" r=".4">
        <stop offset="0" stopColor="#ffe3ad" stopOpacity=".9" /><stop offset=".22" stopColor="#ffb36b" stopOpacity=".45" />
        <stop offset="1" stopColor="#ff8a4a" stopOpacity="0" />
      </radialGradient>
    </defs>
    <rect width="1200" height="760" fill="url(#wp-sky)" />
    <rect width="1200" height="760" fill="url(#wp-sun)" />
    <path d="M0 450C120 400 220 360 330 392S520 340 640 376S860 322 980 362S1140 342 1200 352V760H0Z" fill="#8a3d27" opacity=".7" />
    <path d="M0 530C140 470 260 460 380 490S600 430 720 470S940 440 1060 480S1170 460 1200 470V760H0Z" fill="#572a1c" />
    <path d="M0 605C160 555 300 565 420 590S640 540 780 575S1000 555 1120 585L1200 580V760H0Z" fill="#32180f" />
    <path d="M0 690C200 650 360 665 520 680S820 640 1000 670S1150 660 1200 665V760H0Z" fill="#190b07" />
  </svg>;
}

function AgentCards({ state, error }) {
  const events = state?.events || [];
  const local = ([, agent]) => agent.provider === 'Local' ? 0 : 1;
  return Object.entries(state?.agents || {}).sort((x, y) => local(x) - local(y)).map(([name, session]) => <article className="agentCard" key={name}>
    <small>{session.provider}</small><header><h3>{name}</h3><span className="status" data-status={error ? 'Disconnected' : session.status}>{error ? 'Disconnected' : session.status}</span></header>
    {events.filter(e => e.agent === name).slice(MANAGED ? -6 : 0).map((e,i) => <div className="outputRow" key={i}><time>{e.time}</time><span>{['result','setup','error'].includes(e.action) ? e.target + ' · ' + e.reason : e.action + ' / ' + e.target}</span><b className={'verdict ' + e.verdict}>{e.verdict}</b></div>)}
  </article>);
}

function ScreenRecording({ state, error, command, signedIn, control }) {
  const agents = Object.values(state?.agents || {});
  const events = state?.events || [];
  const live = agents.filter(agent => agent.status === 'Running').length;
  const elapsed = useElapsed(state?.id, state?.running);
  const clock = useClock();
  const last = events[events.length - 1];
  return <figure className="laptop rec" aria-label="Live agent run on a laptop screen">
    <div className="laptopLid"><div className="laptopScreen">
    <span className="laptopNotch" aria-hidden="true"><i /></span>
    <div className="recStage"><Wallpaper />
      <div className="menuBar">
        <span className="menuLeft"><b>TrustAgent</b><span>File</span><span>View</span><span>Run</span></span>
        <span className="menuRight"><span className="menuRec"><i className="recDot" data-on={!!state?.running && !error} />{state?.running ? elapsed : 'ended'}</span><span>run {state?.id || 0}</span><span>{clock}</span></span>
      </div>
      <div className="app">
        <div className="appBar">
          <span className="appPill"><svg {...icon}><path d="M3.5 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z" /></svg>trustagent / demo</span>
          <span className="appPill active">Run {state?.id || '–'}<b>{agents.length}</b></span>
          <span className="appSpacer" />
          <span className="appChip"><i className={'dot' + (live ? ' running' : ' finished')} />{error ? 'offline' : live + ' live'}</span>
          <span className="appTally hideSm" title={events.length + " events"}>{['ALLOW', 'BLOCK', 'STOP'].map(v =>
            <span key={v} className={'verdict ' + v}>{v} {events.filter(e => e.verdict === v).length}</span>)}</span>
        </div>
        <div className="appBody">
          <div className="appRail" role="navigation" aria-label="Page sections">
            {railLinks.map(([href, label, path], i) => <a key={href} href={href} title={label} aria-label={label} aria-current={i === 0 ? 'true' : undefined}><svg {...icon}>{path}</svg></a>)}
          </div>
          <div className="appCanvas">
            {error && <p role="alert">{error}</p>}
            {MANAGED && !signedIn ? <p><a href="#signin">Sign in with the workspace code to view traffic.</a></p>
              : !state && !error && <p role="status">Connecting to the gateway…</p>}
            {MANAGED && signedIn && state && !state.id && <p role="status">{control.starting ? 'Preparing the sandbox…' : 'No managed sessions yet.'}</p>}
            <div className="appCards"><AgentCards state={state} error={error} /></div>
          </div>
        </div>
        <div className="appFoot">
          <span className="appChip hideSm">{MANAGED ? 'Local dashboard' : '127.0.0.1:8787'}</span>
          <div className="appCenter">
            <div className="appActions">
              <a href="#console">Open console <span aria-hidden="true">↗</span></a>
              {MANAGED ? <button disabled={control.disabled} onClick={() => command(control.action)}>{control.label}</button>
                : <button disabled={!state || !!error} onClick={() => command(state.running ? 'stop' : 'start')}>{state?.running ? '■ Stop run' : '▶ Run again'}</button>}
              <a href="#architecture">How it works</a>
            </div>
            <div className="appPrompt">
              <span className="appAvatar" aria-hidden="true"><span className="bot mini"><i /><i /></span></span>
              <code>{last ? last.agent + ' · ' + last.action + ' ' + last.target : 'Waiting for the first event…'}</code>
              {last && <b className={'verdict ' + last.verdict}>{last.verdict}</b>}
            </div>
          </div>
        </div>
      </div>
    </div>
    </div></div>
    <div className="laptopBase" aria-hidden="true"><span /></div>
  </figure>;
}

export function LiveWorkspace({ full = false, ...props }) {
  if (full) return MANAGED ? <ManagedConsole {...props} /> : <AgentIDE {...props} />;
  const { state, error, command, signedIn, pending, session } = props;
  const stopping = state?.run?.status === 'STOPPING';
  const stop = canStop(state?.run);
  const control = {
    action: stop ? 'stop' : 'start',
    disabled: Boolean(pending || stopping || state?.starting || (session && state?.run?.id !== session)),
    label: stopping ? 'Stopping…' : stop ? '■ Stop run' : state?.starting ? 'Starting…' : '▶ Run rehearsal',
    starting: state?.starting,
  };
  return <section id="live" className="workspace">
    <div className="workspaceHeading"><div><small>TRUSTAGENT / WORKSPACE</small><h2>{MANAGED ? 'Managed agent activity' : 'Live agent demo'}</h2></div></div>
    <p>{MANAGED ? 'Watch gateway decisions from a managed session or run the scripted sandbox rehearsal.'
      : 'Three Claude Code and three Codex sessions analyze the public Iris dataset. A local reviewer exercises the gateway’s block and stop policies.'}</p>
    <ScreenRecording state={MANAGED ? previewState(state) : state}
      error={error || state?.startError || state?.run?.stopError} command={command} signedIn={signedIn} control={control} />
  </section>;
}
