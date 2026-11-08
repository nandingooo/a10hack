import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { LiveWorkspace, useGateway } from './LiveWorkspace.jsx';
import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import './styles.css';

function highlightHeadline(event) {
  const line = event.currentTarget;
  const bounds = line.getBoundingClientRect();
  line.style.setProperty('--light-x', (event.clientX - bounds.left) + 'px');
  line.style.setProperty('--light-y', (event.clientY - bounds.top) + 'px');
}

function HeroHeadline() {
  return (
    <h1>
      {['Give your agents', 'a safety boundary.'].map((text, index) => (
        <React.Fragment key={text}>
          {index > 0 && <br />}
          <span className="headlineLine" onPointerDown={highlightHeadline}
            onPointerMove={highlightHeadline}>{text}</span>
        </React.Fragment>
      ))}
    </h1>
  );
}

function Brand() {
  return <a className="brand" href="#top" aria-label="TrustAgent home"><span className="mark" aria-hidden="true"><span className="bot mini"><i/><i/></span></span>TrustAgent</a>;
}

const features = [
  ['box','Sandbox','The demo agents run in one shared workspace. Sensors intercept tool calls and outbound requests before they leave.'],
  ['queue','Context queue','Every read adds a labeled entry. Trust and sensitivity stay separate, so a public README and a credential carry different risks.'],
  ['guard','Central guard','A single policy checks each action against the session history. A blocked request stays visible with its reason.']
];
function WorkspaceTools({ mode, launch }) {
  const menu = React.useRef(null);
  const close = () => menu.current?.hidePopover();
  const status = { preview: 'Demo ready', running: 'Demo live', manual: 'Stopped', finished: 'Run ended' }[mode];
  return (
    <div className="workspaceTools">
      <span className="runStatus"><i className={'dot ' + mode} />{status}</span>
      <button className="toolsTrigger" popoverTarget="workspace-tools" aria-label="Workspace tools" title="Workspace tools">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
          <rect x="2.5" y="7" width="19" height="14" rx="3" />
          <path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M3 12q9 5 18 0M12 13v3" />
        </svg>
      </button>
      <div ref={menu} id="workspace-tools" popover="auto" className="toolsPanel">
        <strong>Workspace tools</strong>
        <button onClick={() => { close(); launch(); }}><span aria-hidden="true">▷</span>{mode === 'running' ? 'View active demo' : 'Launch demo'}</button>
        <a href="#console" onClick={close}><span aria-hidden="true">≡</span>Session traffic</a>
        <a href="#architecture" onClick={close}><span aria-hidden="true">◇</span>Architecture</a>
        <a href="#faq" onClick={close}><span aria-hidden="true">?</span>FAQ</a>
      </div>
    </div>
  );
}

const providerIcons = {
  google: <svg viewBox="0 0 18 18" aria-hidden="true">
    <path fill="#EA4335" d="M9 3.48c1.69 0 2.83.73 3.48 1.34l2.54-2.48C13.46.89 11.43 0 9 0 5.48 0 2.44 2.02.96 4.96l2.91 2.26C4.6 5.05 6.62 3.48 9 3.48z" />
    <path fill="#4285F4" d="M17.64 9.2c0-.74-.06-1.28-.19-1.84H9v3.34h4.96c-.1.83-.64 2.08-1.84 2.92l2.84 2.2c1.7-1.57 2.68-3.88 2.68-6.62z" />
    <path fill="#FBBC05" d="M3.88 10.78A5.54 5.54 0 0 1 3.58 9c0-.62.11-1.22.29-1.78L.96 4.96A9 9 0 0 0 0 9c0 1.45.35 2.82.96 4.04l2.92-2.26z" />
    <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.84-2.2c-.76.53-1.78.9-3.12.9-2.38 0-4.4-1.57-5.12-3.74L.97 13.04C2.45 15.98 5.48 18 9 18z" />
  </svg>,
  github: <svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" /></svg>,
  aws: <svg viewBox="0 0 24 24" aria-hidden="true"><text x="12" y="12.5" textAnchor="middle" fill="currentColor" style={{font: '700 8.5px var(--font-sans)'}}>aws</text><path d="M4.5 15.6c4.4 2.9 10.6 2.9 15 0" fill="none" stroke="#FF9900" strokeWidth="1.6" strokeLinecap="round" /><path d="M17.4 14.6l2.3.9-.6 2.4" fill="none" stroke="#FF9900" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>,
};
const oauthProviders = [
  ['google', 'Continue with Google', 'Gmail · Workspace', 'TRUSTAGENT_GOOGLE_CLIENT_ID and TRUSTAGENT_GOOGLE_CLIENT_SECRET'],
  ['github', 'Continue with GitHub', '', 'TRUSTAGENT_GITHUB_CLIENT_ID and TRUSTAGENT_GITHUB_CLIENT_SECRET'],
];

function AwsBuilderId({ enabled, onSignedIn }) {
  const [flow, setFlow] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  useEffect(() => {
    if (!flow) return;
    let active = true, timer;
    async function poll() {
      try {
        const res = await fetch('/auth/aws/poll', { method: 'POST', headers: { 'X-Airlock-Demo': '1' } });
        if (res.status === 200) { const data = await res.json(); if (active) onSignedIn(data.name); return; }
        if (res.status !== 202) {
          const data = await res.json().catch(() => ({}));
          if (active) { setFlow(null); setMessage(res.status === 410 || data.error === 'expired' ? 'The code expired. Start again.' : 'AWS sign-in was denied or canceled.'); }
          return;
        }
      } catch { /* network blip: keep polling until the code expires */ }
      if (active) timer = setTimeout(poll, flow.interval * 1000);
    }
    timer = setTimeout(poll, flow.interval * 1000);
    return () => { active = false; clearTimeout(timer); };
  }, [flow]);
  async function start() {
    setBusy(true); setMessage('');
    try {
      const res = await fetch('/auth/aws/start', { method: 'POST', headers: { 'X-Airlock-Demo': '1' } });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw Error(data.error || 'AWS sign-in is not available on this gateway.');
      setFlow(data);
    } catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }
  if (flow) return <div className="awsFlow" role="group" aria-label="AWS Builder ID sign-in">
    <span className="awsStep">1 · Confirm this code on AWS</span>
    <code className="userCode">{flow.userCode}</code>
    <a className="primary" href={flow.verificationUri} target="_blank" rel="noopener noreferrer">Open AWS sign-in <span aria-hidden="true">↗</span></a>
    <span className="awsStep"><i className="dot running" aria-hidden="true" />2 · Waiting for approval…</span>
    <button type="button" className="textButton" onClick={() => setFlow(null)}>Cancel</button>
  </div>;
  return <>
    <button type="button" className="providerButton" disabled={!enabled || busy} onClick={start}
      title={enabled ? undefined : 'AWS Builder ID sign-in is turned off on this gateway (TRUSTAGENT_AWS_BUILDER_ID=0).'}>
      <span className="providerIcon">{providerIcons.aws}</span>Continue with AWS Builder ID
      {(busy || !enabled) && <span className="providerMeta">{busy ? 'Starting…' : 'Off'}</span>}
    </button>
    {message && <p role="alert">{message}</p>}
  </>;
}

function SignIn({ profile, setProfile, failed }) {
  const [message, setMessage] = useState(failed ? 'Sign-in was canceled or could not be completed.' : '');
  const signedIn = name => { setProfile({ ...profile, name }); setMessage(''); location.hash = 'console'; };
  async function submit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const res = await fetch(profile.name ? '/auth/logout' : '/auth/local', {
        method:'POST', headers:{'X-Airlock-Demo':'1'}, body:profile.name ? '' : new FormData(form).get('code')
      });
      if (!res.ok) throw Error();
      const data = await res.json();
      if (data.name) return signedIn(data.name);
      setProfile({ ...profile, name: null }); setMessage(''); location.hash = 'top';
    } catch { setMessage(profile.name ? 'Sign-out failed. Check the gateway.' : 'That code did not match. Check the code printed in your gateway terminal.'); }
  }
  const missing = oauthProviders.filter(([id]) => !profile.providers.includes(id));
  return <section className="signinPage"><div className="signinCard"><div className="bot signinBot" aria-hidden="true"><i/><i/></div><Brand/>
    <h1>{profile.name ? 'Your account' : 'Sign in to TrustAgent'}</h1>
    {profile.name ? <p>Signed in as <b>{profile.name}</b></p> : <>
      <p>Choose an account to continue.</p>
      <div className="providerList">
        {oauthProviders.map(([id, label, meta, env]) => profile.providers.includes(id)
          ? <a key={id} className="providerButton" href={'/auth/start/' + id}><span className="providerIcon">{providerIcons[id]}</span>{label}<span className="providerMeta">{meta}</span></a>
          : <button key={id} type="button" className="providerButton" disabled title={'Set ' + env + ' on the gateway host, then restart it.'}><span className="providerIcon">{providerIcons[id]}</span>{label}<span className="providerMeta">Setup needed</span></button>)}
        <AwsBuilderId enabled={profile.providers.includes('aws')} onSignedIn={signedIn} />
      </div>
      {missing.length > 0 && <small className="providerNote">{missing.map(([, label]) => label.replace('Continue with ', '')).join(' and ')} sign-in {missing.length > 1 ? 'need' : 'needs'} OAuth client credentials on the gateway. See the README.</small>}
      <div className="divider"><span>or use the workspace code</span></div>
    </>}
    <form onSubmit={submit}>{!profile.name && <label>Workspace access code<input autoComplete="off" type="password" name="code" required/><small>Use the code printed in your gateway terminal.</small></label>}
      <button className="primary">{profile.name ? 'Sign out' : 'Sign in'}</button></form>
    {message && <p role="alert">{message}</p>}</div></section>;
}

function App() {
  const { state, error, command } = useGateway();
  const [hash, setHash] = useState(location.hash);
  const [theme, setTheme] = useState(() => localStorage.getItem('airlock-theme') || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  const [profile, setProfile] = useState({name:null, providers:[]});
  useEffect(() => { fetch('/auth/me').then(r => r.json()).then(setProfile).catch(() => {}); }, []);
  const accountPage = ['#signin','#account','#signin-error'].includes(hash);
  const consolePage = hash === '#console';
  useEffect(() => {
    const changed = () => setHash(location.hash);
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  useEffect(() => {
    if (consolePage) window.scrollTo(0, 0);
    else document.getElementById(hash.slice(1))?.scrollIntoView();
  }, [hash, consolePage]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('airlock-theme', theme);
  }, [theme]);
  const launch = () => { command('start'); location.hash = 'console'; };
  const mode = state?.running ? 'running' : state?.id ? 'finished' : 'preview';
  return <main id="top"><nav><Brand/><div className="navLinks"><a href="#console">Console</a><a href="#architecture">Architecture</a><a href="#faq">FAQ</a></div><div className="navControls"><a className="signinLink" href={profile.name ? "#account" : "#signin"}>{profile.name ? "Account" : "Sign in"}</a><button className="themeSwitch" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? '☀ Light' : '☾ Dark'}</button><WorkspaceTools mode={mode} launch={launch} /></div></nav>
    {accountPage ? <SignIn profile={profile} setProfile={setProfile} failed={hash === "#signin-error"}/> : consolePage ? <LiveWorkspace full state={state} error={error} command={command} /> : <>
    <section className="hero"><div className="eyebrow"><i className="dot"/> CLI AGENT CONTROL PLANE</div><HeroHeadline /><p>See what your coding agent reads, where its traffic goes,<br className="desktop"/> and why the guard steps in.</p><div className="heroActions"><button className="primary" onClick={() => document.getElementById('live').scrollIntoView()}>Watch live agents <span>↗</span></button><a href="#architecture">How it works ↓</a></div><code className="heroCmd"><span aria-hidden="true">$</span> python3 demo/gateway.py</code></section>
    <LiveWorkspace state={state} error={error} command={command} />
    <section className="architecture" id="architecture"><div className="eyebrow">ARCHITECTURE</div><h2>From a file read to a verdict.</h2><div className="cards">{features.map(([id,title,body]) => <article key={id}><div className={'glyph '+id} aria-hidden="true">{id==='box'?'⬡':id==='queue'?'≡':'◇'}</div><h3>{title}</h3><p>{body}</p></article>)}</div></section>
    <section id="faq"><div className="eyebrow">FAQ</div><h2>Inside TrustAgent.</h2>{[
      ['What happens when an action is blocked?', 'The request is denied and the session can continue. Open the Console action log to inspect its source labels and policy reason.'],
      ['How precise is the context queue?', 'The MVP considers the entire session history. A previously read secret can trigger a block even when the current action is unrelated to that file.'],
      ['Does this demo launch a local CLI?', 'The gateway launches authenticated Claude Code and Codex CLIs for six public-data tasks and supervises one local policy reviewer.']
    ].map(([q,a])=><details key={q}><summary>{q}</summary><p>{a}</p></details>)}</section>
    <section className="closingBanner" aria-labelledby="closing-title">
      <h2 id="closing-title">TrustAgent</h2>
      <p>Even the smallest agent leaves a trail.</p>
      <a href="#console">Follow a session <span aria-hidden="true">↗</span></a>
      <div className="bot trailBot" aria-hidden="true"><i/><i/></div>
    </section>
    </>}<footer className="siteFooter"><Brand/>
      <div><h2>Workspace</h2><a href="#console">Agent console</a><a href="#live">Live demo</a></div>
      <div><h2>Resources</h2><a href="#architecture">Architecture</a><a href="#faq">FAQ</a></div>
      <div><h2>Account</h2><a href={profile.name ? '#account' : '#signin'}>{profile.name ? 'Your account' : 'Sign in'}</a><a href="#top">Back to top ↑</a></div>
    </footer></main>;
}
createRoot(document.getElementById('root')).render(<App/>);
