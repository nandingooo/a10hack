export const AGENT_CLIENTS = [
  { id: 'claude-code', label: 'Claude Code' },
  { id: 'codex', label: 'Codex' },
];

/** Client identity is display metadata, separate from trust labels and policy. */
export function agentClient(session) {
  const value = String(session?.agent || session?.agent_type || '').trim().toLowerCase().replace(/[ _]+/g, '-');
  if (['codex', 'codex-cli', 'openai-codex'].includes(value)) return AGENT_CLIENTS[1];
  if (['claude', 'claude-code', 'anthropic-claude-code'].includes(value)) return AGENT_CLIENTS[0];
  return { id: 'unknown', label: 'Other sessions' };
}

export function groupAgents(sessions) {
  const groups = AGENT_CLIENTS.map(client => ({ ...client, sessions: [] }));
  const other = { id: 'unknown', label: 'Other sessions', sessions: [] };
  for (const session of sessions) {
    const client = agentClient(session);
    (groups.find(group => group.id === client.id) || other).sessions.push(session);
  }
  if (other.sessions.length) groups.push(other);
  return groups;
}
