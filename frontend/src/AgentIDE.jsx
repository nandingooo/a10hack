import React, { useEffect, useRef, useState } from 'react';
import source from '../demo/agent.py?raw';
import providerSource from '../demo/provider.py?raw';
import { api, Refusal } from './LiveWorkspace.jsx';
import './ide.css';

function highlight(line) {
  return line.split(/(f?"[^"]*"|\b(?:def|for|in|if|return|import)\b|\b\d+\b)/g).map((part, i) =>
    i % 2 ? <span key={i} className={part.includes('"') ? 'literal' : 'keyword'}>{part}</span> : part
  );
}

const clamp = (value, min, max) => Math.min(Math.max(value, min), Math.max(min, max));

/* A pane size remembered per browser. Storage can be unavailable, so every access is guarded. */
function useStoredSize(key, initial) {
  const [size, setSize] = useState(() => {
    try { const stored = Number(localStorage.getItem(key)); return stored > 0 ? stored : initial; }
    catch { return initial; }
  });
  useEffect(() => { try { localStorage.setItem(key, String(Math.round(size))); } catch { /* ignore */ } }, [key, size]);
  return [size, setSize];
}

/* VS Code-style sash. The resized pane sits after the sash (below or to the right),
   so dragging toward the start of the axis makes the pane bigger. */
function Sash({ orientation, size, min, max, onResize, onReset, label, controls }) {
  const horizontal = orientation === 'horizontal';
  function begin(event) {
    if (event.button !== 0) return;
    event.preventDefault();
    const handle = event.currentTarget;
    const origin = horizontal ? event.clientY : event.clientX;
    const startSize = size;
    const limit = max();
    handle.setPointerCapture(event.pointerId);
    handle.classList.add('active');
    document.body.classList.add(horizontal ? 'resizingRows' : 'resizingCols');
    const move = e => onResize(clamp(startSize - ((horizontal ? e.clientY : e.clientX) - origin), min, limit));
    const end = () => {
      handle.classList.remove('active');
      document.body.classList.remove('resizingRows', 'resizingCols');
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', end);
      handle.removeEventListener('pointercancel', end);
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', end);
    handle.addEventListener('pointercancel', end);
  }
  function key(event) {
    const step = event.shiftKey ? 64 : 16;
    const grow = horizontal ? 'ArrowUp' : 'ArrowLeft';
    const shrink = horizontal ? 'ArrowDown' : 'ArrowRight';
    if (event.key === grow) onResize(clamp(size + step, min, max()));
    else if (event.key === shrink) onResize(clamp(size - step, min, max()));
    else if (event.key === 'Enter') onReset();
    else return;
    event.preventDefault();
  }
  return <div className={'sash ' + orientation} role="separator" tabIndex={0} aria-label={label} aria-controls={controls}
    aria-orientation={horizontal ? 'horizontal' : 'vertical'} aria-valuenow={Math.round(size)} aria-valuemin={min}
    title={label + ' · drag to resize, double-click to reset'} onPointerDown={begin} onDoubleClick={onReset} onKeyDown={key} />;
}

function Notice({ role, children, onClose }) {
  return <div className={'notice ' + role} role={role}><span>{children}</span>
    <button type="button" className="iconButton" aria-label="Dismiss" title="Dismiss" onClick={onClose}>
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" /></svg>
    </button></div>;
}

const TERMINAL_DEFAULT = 200;
const INSPECTOR_DEFAULT = 340;

export default function AgentIDE({ state, error, command, canRun, notice, setNotice }) {
  const [chosenTask, chooseTask] = useState('');
  const [extraTabs, setExtraTabs] = useState([]);
  const [closedTasks, setClosedTasks] = useState([]);
  const nextTab = useRef(1);
  const [chosenAgent, select] = useState('');
  const [open, setOpen] = useState(true);
  const [adding, setAdding] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [dismissedError, setDismissedError] = useState('');
  const [terminalHeight, setTerminalHeight] = useStoredSize('ta-terminal-height', TERMINAL_DEFAULT);
  const [inspectorWidth, setInspectorWidth] = useStoredSize('ta-inspector-width', INSPECTOR_DEFAULT);
  const leftPane = useRef(null);
  const layout = useRef(null);
  useEffect(() => { if (!error) setDismissedError(''); }, [error]);

  const sessions = Object.entries(state?.sessions || {});
  const tabs = [
    ...sessions.filter(([, item]) => !closedTasks.includes(item.task)).map(([, item]) => ({ key: item.task, task: item.task })),
    ...extraTabs,
  ];
  const selected = tabs.find(tab => tab.key === chosenTask) || tabs[0];
  const selectedIndex = tabs.findIndex(tab => tab.key === selected?.key);
  const [sessionId, session] = sessions.find(([, item]) => item.task === selected?.task) || [];

  function resetPanels() { setAdding(false); setMessage(''); }
  function newTab() {
    const key = 'view-' + nextTab.current++;
    setExtraTabs(previous => [...previous, { key, task: '' }]);
    chooseTask(key);
    resetPanels();
    requestAnimationFrame(() => document.getElementById('session-choice')?.focus());
  }
  function closeTab(tab) {
    const index = tabs.findIndex(item => item.key === tab.key);
    const neighbour = tabs[index + 1] || tabs[index - 1];
    if (extraTabs.some(item => item.key === tab.key)) setExtraTabs(previous => previous.filter(item => item.key !== tab.key));
    else setClosedTasks(previous => [...previous, tab.task]);
    if (tab.key === selected?.key) chooseTask(neighbour?.key || '');
    resetPanels();
    requestAnimationFrame(() => document.querySelector('.sessionStrip [role=tab][aria-selected=true]')?.focus());
  }
  /* Picking a session in a new tab reopens (or jumps to) that session's own tab, so no duplicates appear. */
  function chooseSessionForTab(task) {
    if (!task) return;
    const placeholder = selected.key;
    setClosedTasks(previous => previous.filter(item => item !== task));
    setExtraTabs(previous => previous.filter(tab => tab.key !== placeholder));
    chooseTask(task);
    setAdding(false);
    requestAnimationFrame(() => document.querySelector('.sessionStrip [role=tab][aria-selected=true]')?.focus());
  }

  const subtasks = Object.entries(session?.subtasks || {});
  const members = subtasks.flatMap(([, names]) => names);
  const agent = members.includes(chosenAgent) ? chosenAgent : members[0];
  async function assign(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setSaving(true);
    try {
      await api('add-agent', 'POST', { session: sessionId, subtask: form.get('subtask'), provider: form.get('provider') });
      setAdding(false);
      setMessage('Agent assigned. It will start on the next run.');
    } catch (failure) {
      setMessage(failure instanceof Refusal ? failure.message : 'Could not add the agent. Check your connection and try again.');
    }
    finally { setSaving(false); }
  }
  const local = agent === 'Reviewer';
  const symbol = local ? 'review' : 'build_prompt';
  const lines = (local ? source : providerSource).trimEnd().split('\n');
  const start = lines.findIndex(line => line.startsWith('def ' + symbol + '('));
  const end = lines.indexOf('', start);
  const events = (state?.events || []).filter(event => event.session_id === sessionId);
  const output = events.filter(event => event.agent === agent);
  const terminalMax = () => (leftPane.current?.clientHeight || 600) - 180;
  const inspectorMax = () => (layout.current?.clientWidth || 1000) - 380;

  return <section className="ide" aria-label="Agent console">
    <header className="ideBar"><h1>Agent console</h1><span className="runtime">Python 3</span>
      {canRun
        ? <button className="runAgent" disabled={!state || !!error} onClick={() => command(state.running ? 'stop' : 'start')}>{state?.running ? '■ Stop agents' : '▶ Run agents'}</button>
        : <a className="runAgent" href="#signin" title="Anyone can watch. Workspace operators start runs.">Sign in to run</a>}
      <button disabled={!canRun || !session || !!error || saving} aria-expanded={adding} onClick={() => { setAdding(!adding); setMessage(''); }}>＋ Add agent</button>
      <button aria-controls="ideActions" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? 'Collapse' : 'Open'} actions</button></header>
    <div className="browserTabs"><div className="sessionStrip" role="tablist" aria-label="Task sessions">
      {tabs.map((tab, index) => {
        const item = sessions.find(([, value]) => value.task === tab.task)?.[1];
        const tasks = Object.values(item?.subtasks || {});
        const count = tasks.flat().length;
        const isSelected = tab.key === selected?.key;
        const name = tab.task || 'New tab';
        return <div className="sessionTab" key={tab.key} data-selected={isSelected}>
          <button role="tab" id={'session-tab-' + index} aria-controls="session-panel" aria-selected={isSelected} tabIndex={isSelected ? 0 : -1}
            title={name + ' · Delete closes the tab'}
            onKeyDown={e => {
              if (e.key === 'Delete') { e.preventDefault(); closeTab(tab); return; }
              const n = tabs.length;
              const next = { ArrowRight: (index + 1) % n, ArrowLeft: (index + n - 1) % n, Home: 0, End: n - 1 }[e.key];
              if (next !== undefined) {
                e.preventDefault();
                const target = e.currentTarget.closest('[role=tablist]').querySelectorAll('[role=tab]')[next];
                target.focus(); target.click();
              }
            }}
            onClick={() => { chooseTask(tab.key); resetPanels(); }}>
            <strong>{name}</strong>
            {item && <span>{count} {count === 1 ? 'agent' : 'agents'} · {tasks.length} {tasks.length === 1 ? 'subtask' : 'subtasks'}</span>}
          </button>
          <button type="button" className="tabClose" tabIndex={-1} aria-label={'Close ' + name + ' tab'} title="Close tab" onClick={() => closeTab(tab)}>
            <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4.5 4.5l7 7M11.5 4.5l-7 7" /></svg>
          </button>
        </div>;
      })}
    </div><button className="newSessionTab" onClick={newTab} aria-label="Open new tab" title="Open new tab">+</button></div>
    {extraTabs.some(tab => tab.key === selected?.key) && <div className="tabChoice">
      <label>Task session <select id="session-choice" value={selected.task} onChange={e => chooseSessionForTab(e.target.value)}>
        <option value="">Choose a session</option>{sessions.map(([id, item]) => <option key={id}>{item.task}</option>)}</select></label>
    </div>}
    {adding && session && <form className="assignForm" onSubmit={assign}>
      <strong>Add to {session.task}</strong>
      <label>Provider <select name="provider"><option>Claude Code</option><option>Codex</option></select></label>
      <label>Subtask <select name="subtask">{subtasks.map(([title]) => <option key={title}>{title}</option>)}</select></label>
      <button disabled={saving}>Assign to next run</button><button type="button" disabled={saving} onClick={() => setAdding(false)}>Cancel</button>
    </form>}
    {message && <Notice role="status" onClose={() => setMessage('')}>{message}</Notice>}
    {notice && <Notice role="status" onClose={() => setNotice('')}>{notice}</Notice>}
    {error && error !== dismissedError && <Notice role="alert" onClose={() => setDismissedError(error)}>{error}</Notice>}
    {session ? <div id="session-panel" ref={layout} role="tabpanel" aria-labelledby={'session-tab-' + selectedIndex}
      className={'ideLayout' + (open ? ' withInspector' : '')}
      style={{ '--terminal-h': terminalHeight + 'px', '--inspector-w': inspectorWidth + 'px' }}>
      <div className="ideLeft" ref={leftPane}>
        {subtasks.map(([title, names]) => <div className="agentTabs taskGroup" key={title}><strong>{title}</strong>{names.map(name =>
          <button key={name} aria-pressed={agent === name} onClick={() => select(name)}>{state.agents[name].provider} · {name}</button>)}</div>)}
        <div className="filePath">demo / {local ? 'agent.py' : 'provider.py'} / <strong>{symbol}()</strong><span>Read only</span></div>
        <div className="codeView" tabIndex={0} aria-label={agent + ' Python source'}>{lines.slice(start, end < 0 ? undefined : end).map((line, i) =>
          <div className="sourceLine" key={i}><span aria-hidden="true">{start + i + 1}</span><code>{highlight(line)}</code></div>)}</div>
        <Sash orientation="horizontal" size={terminalHeight} min={72} max={terminalMax} onResize={setTerminalHeight}
          onReset={() => setTerminalHeight(TERMINAL_DEFAULT)} label="Resize terminal" controls="terminal-pane" />
        <div className="terminalPane" id="terminal-pane">
          <div className="paneTitle">❯_ Terminal <span>{agent} · {error ? 'Disconnected' : state?.agents[agent]?.status || 'Waiting'}</span></div>
          <div className="terminalOutput" tabIndex={0}>{output.length ? output.map((e, i) => <div key={i}><time>{e.time}</time> <b className={'verdict ' + e.verdict}>{e.verdict}</b> {e.action} {e.target}{['result', 'setup', 'error'].includes(e.action) && <div className="resultText">{e.reason}</div>}</div>) : 'Waiting for agent output…'}</div>
        </div>
      </div>
      {open && <Sash orientation="vertical" size={inspectorWidth} min={240} max={inspectorMax} onResize={setInspectorWidth}
        onReset={() => setInspectorWidth(INSPECTOR_DEFAULT)} label="Resize session actions" controls="ideActions" />}
      <aside id="ideActions" className="ideActions" hidden={!open}><div className="paneTitle">Session actions <span>{events.length} events</span></div>
        <details><summary>Shared queue · {session?.task}</summary>{(session?.queue || []).map((file, i) => <p key={i}><code>{file.agent} · {file.file} · {file.trust} / {file.sensitivity}</code></p>)}</details>
        <div className="actionList">{[...events].reverse().map((e, i) => <div className="actionItem" key={i}><time>{e.time} · {e.agent}</time><div><b className={'verdict ' + e.verdict}>{e.verdict}</b> <strong>{e.target}</strong></div><p>{e.reason}</p>{e.labels && <code>{e.labels.trust} / {e.labels.sensitivity}</code>}</div>)}</div>
      </aside>
    </div> : <div id="session-panel" role="tabpanel" className="emptySession"><div className="bot emptyBot" aria-hidden="true"><i /><i /></div>
      {!state?.id ? (canRun ? 'No run yet. Press Run agents to start one.' : 'No run yet. Anyone can watch once a workspace operator starts one.')
        : tabs.length ? 'Choose a task session to view its agents and activity.' : 'All tabs are closed. Press + to open a session again.'}</div>}
  </section>;
}
