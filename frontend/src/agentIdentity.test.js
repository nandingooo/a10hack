import test from 'node:test';
import assert from 'node:assert/strict';
import { agentClient, groupAgents } from './agentIdentity.js';

test('normalizes explicit Claude Code and Codex identities', () => {
  assert.equal(agentClient({ agent: 'codex' }).label, 'Codex');
  assert.equal(agentClient({ agent_type: 'OpenAI Codex' }).id, 'codex');
  assert.equal(agentClient({ agent: 'Codex CLI' }).id, 'codex');
  assert.equal(agentClient({ agent: 'claude-code' }).label, 'Claude Code');
});

test('never guesses a client from an opaque session ID or missing metadata', () => {
  for (const session of [{}, null, { session_id: 'codex-123' }, { agent: 'unknown' }, { agent: 'other-tool' }]) {
    assert.equal(agentClient(session).id, 'unknown');
  }
});

test('groups mixed clients without changing session identity, order or selection keys', () => {
  const sessions = [
    { session_id: 'c2', agent: 'codex' }, { session_id: 'a1', agent: 'claude-code' },
    { session_id: 'c1', agent: 'codex' }, { session_id: 'legacy' },
  ];
  const groups = groupAgents(sessions);
  assert.deepEqual(groups.map(group => [group.id, group.sessions.map(session => session.session_id)]), [
    ['claude-code', ['a1']], ['codex', ['c2', 'c1']], ['unknown', ['legacy']],
  ]);
  assert.equal(groups[1].sessions[0], sessions[0]);
  assert.equal(groupAgents([]).length, 2);
});
