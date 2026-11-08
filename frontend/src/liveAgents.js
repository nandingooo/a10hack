import { useEffect, useState } from 'react';

const POLL_MS = 1000;
const UNAVAILABLE = 'Dashboard server unavailable. Start python3 frontend/managed.py.';

async function request(path, { method = 'GET', signal } = {}) {
  const response = await fetch('/api/' + path, { method, signal, headers: { 'X-Airlock-Demo': '1' }, cache: 'no-store' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || UNAVAILABLE);
    error.status = response.status;
    throw error;
  }
  return data;
}

/** Polls real hook-mode agents (Claude Code sessions reporting to the local guard). */
export function useLiveAgents(enabled, setProfile) {
  const [state, setState] = useState(null);
  const [session, setSession] = useState('');
  const [error, setError] = useState('');
  const [revision, refresh] = useState(0);

  useEffect(() => {
    if (!enabled) return undefined;
    const controller = new AbortController();
    let timer;
    async function poll() {
      try {
        const query = session ? '?session=' + encodeURIComponent(session) : '';
        const snapshot = await request('live' + query, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setState(snapshot);
        setError('');
      } catch (failure) {
        if (controller.signal.aborted) return;
        if (failure.status === 401) {
          setProfile({ name: null, providers: [] });
          return;
        }
        setError(failure.status ? failure.message : UNAVAILABLE);
      }
      timer = setTimeout(poll, POLL_MS);
    }
    poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [enabled, session, revision, setProfile]);

  async function stop(id) {
    try {
      await request('live/' + encodeURIComponent(id) + '/stop', { method: 'POST' });
      refresh(value => value + 1);
    } catch (failure) {
      setError(failure.status ? failure.message : UNAVAILABLE);
    }
  }

  return { state, error, session, select: setSession, stop };
}

export function relativeTime(ts, now = Date.now() / 1000) {
  if (!ts) return 'no activity yet';
  const seconds = Math.max(0, Math.round(now - ts));
  if (seconds < 60) return seconds + 's ago';
  if (seconds < 3600) return Math.round(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
  return Math.round(seconds / 86400) + 'd ago';
}

/** An unkilled agent that produced an event in the last two minutes is treated as running. */
export const isRunning = (agent, now = Date.now() / 1000) =>
  agent.status !== 'KILLED' && Boolean(agent.last_ts) && now - agent.last_ts < 120;
