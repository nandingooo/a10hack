import { useEffect, useState } from 'react';

export const MANAGED = import.meta.env.MODE !== 'demo';

async function request(path, { method = 'GET', signal, body } = {}) {
  const headers = { 'X-Airlock-Demo': '1' };
  if (body) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api/' + path, {
    method, signal, headers, body: body && JSON.stringify(body), cache: 'no-store',
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || 'Dashboard server unavailable. Start python3 frontend/managed.py.');
    error.status = response.status;
    throw error;
  }
  return data;
}

export function useManagedGateway(enabled, setProfile) {
  const [state, setState] = useState(null);
  const [session, setSession] = useState('');
  const [error, setError] = useState('');
  const [commandError, setCommandError] = useState('');
  const [pending, setPending] = useState(false);
  const [revision, refreshNow] = useState(0);

  useEffect(() => {
    if (!enabled) {
      setState(null);
      setSession('');
      setError('');
      setCommandError('');
      return;
    }
    const controller = new AbortController();
    let timer;
    async function refresh() {
      try {
        const query = session ? '?session=' + encodeURIComponent(session) : '';
        const snapshot = await request('state' + query, { signal: controller.signal });
        if (!controller.signal.aborted) {
          setState(snapshot);
          setError('');
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error.status === 401) {
          setProfile({ name: null, providers: [] });
          return;
        }
        if (error.status === 404 && session) {
          setSession('');
          return;
        }
        setError(error.status ? error.message : 'Dashboard server unavailable. Start python3 frontend/managed.py.');
      }
      if (!controller.signal.aborted) timer = setTimeout(refresh, 1000);
    }
    refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [enabled, session, revision, setProfile]);

  function select(id) {
    setCommandError('');
    setSession(id);
  }

  async function command(action, scenario) {
    if (!enabled) {
      location.hash = 'signin';
      return;
    }
    if (pending) return;
    const id = state?.run?.id;
    if (action === 'stop' && !id) return;
    setPending(true);
    setCommandError('');
    try {
      await request(action === 'start' ? 'start' : 'runs/' + encodeURIComponent(id) + '/stop', {
        method: 'POST', body: action === 'start' && scenario ? { scenario } : undefined,
      });
      if (action === 'start') setSession('');
      refreshNow(current => current + 1);
    } catch (error) {
      if (error.status === 401) {
        setProfile({ name: null, providers: [] });
        location.hash = 'signin';
      } else {
        setCommandError(error.status ? error.message : 'Could not reach the dashboard server.');
      }
    } finally {
      setPending(false);
    }
  }

  return { state, error: commandError || error, command, select, pending, session };
}

export const canStop = run => ['RUNNING', 'UNAVAILABLE'].includes(run?.status);

export const runStatus = status => ({
  PREPARED: 'Preparing', RUNNING: 'Running', STOPPING: 'Stopping',
  STOPPED: 'Stopped', UNAVAILABLE: 'Gateway unavailable',
})[status] || 'Waiting';

export const eventTime = event => new Date(event.ts * 1000).toLocaleTimeString();

export function previewState(state) {
  const run = state?.run;
  const name = run?.scenarioTitle || 'Managed session';
  return state && {
    id: run?.id.slice(0, 8),
    running: run?.status === 'RUNNING',
    agents: run ? { [name]: { provider: 'Managed sandbox', status: runStatus(run.status) } } : {},
    events: state.events.filter(event => event.type === 'decision').map(event => ({
      agent: name, time: eventTime(event), action: event.op, target: event.target,
      verdict: event.decision.toUpperCase(), reason: event.reason,
    })),
  };
}
