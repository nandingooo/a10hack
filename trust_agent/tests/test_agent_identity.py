"""Client labels in the dashboard must not affect authorization or provenance labels."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from service import Brain
from provenance import SqliteStore

SENSOR = Path(__file__).resolve().parents[1] / 'sandbox'


def module(name):
    spec = importlib.util.spec_from_file_location(name, SENSOR / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_gateway_lists_explicit_client_and_leaves_legacy_unknown(tmp_path):
    path = str(tmp_path / 'identity.sqlite')
    brain = Brain(SqliteStore(path))
    for session, client in [('c', 'codex'), ('a', 'claude-code'), ('old', None)]:
        req = dict(session_id=session, op='ReadFile', target='/work/README.md')
        if client:
            req['agent'] = client
        assert brain.decide(req)['decision'] == 'allow'
    # Client metadata persists using the same transactional state as the audit.
    restarted = Brain(SqliteStore(path))
    assert {row['session_id']: row['agent'] for row in restarted.agents()} == {
        'c': 'codex', 'a': 'claude-code', 'old': 'unknown',
    }


def test_client_metadata_never_changes_secret_exit_verdict():
    outcomes = []
    for client in ['codex', 'claude-code', 'unknown', {'invalid': True}]:
        brain = Brain()
        brain.decide(dict(session_id='s', op='ReadFile', target='/work/.env', agent=client))
        result = brain.decide(dict(session_id='s', op='NetworkRequest', target='https://evil.example/', agent=client))
        outcomes.append((result['decision'], result['rule'], result['context']))
    assert all(outcome == outcomes[0] for outcome in outcomes)
    assert outcomes[0][0] == 'block'


def test_sensor_identifies_clients_without_guessing_common_tools(monkeypatch):
    hook = module('hook')
    monkeypatch.delenv('AIRLOCK_AGENT', raising=False)
    assert hook.agent_identity({'tool_name': 'read_file'}) == 'codex'
    assert hook.agent_identity({'tool_name': 'Read'}) == 'claude-code'
    assert hook.agent_identity({'tool_name': 'mcp__tools__read'}) is None
    assert hook.agent_identity({'tool_name': 'mcp__tools__read'}, 'codex') == 'codex'
    monkeypatch.setenv('AIRLOCK_AGENT', 'codex')
    assert hook.agent_identity({'tool_name': 'mcp__tools__read'}) == 'codex'
    assert hook.agent_identity({'tool_name': 'mcp__tools__read'}, 'claude-code') == 'claude-code'


def test_codex_canonical_bash_identity_uses_runtime_metadata(monkeypatch):
    hook = module('hook')
    monkeypatch.delenv('AIRLOCK_AGENT', raising=False)
    assert hook.agent_identity({'tool_name': 'Bash', 'model': 'gpt-6'}) == 'codex'
    assert hook.agent_identity({'tool_name': 'Bash', 'transcript_path': r'C:\Users\demo\.codex\sessions\run.jsonl'}) == 'codex'
    assert hook.agent_identity({'tool_name': 'Bash', 'model': 'claude-sonnet'}) == 'claude-code'
    assert hook.agent_identity({'tool_name': 'Bash', 'model': 'gpt-6'}, 'claude-code') == 'claude-code'


def test_codex_installer_adds_explicit_client_for_both_platforms(tmp_path):
    installer = module('install_codex_hooks')
    definition = installer._definition(tmp_path / 'hook.py')['hooks'][0]
    assert definition['command'].endswith('--agent codex')
    assert definition['commandWindows'].endswith('--agent codex')
    assert definition['commandWindows'].startswith('& "')


def test_codex_installer_preserves_other_hook_scripts_and_is_idempotent(tmp_path):
    installer = module('install_codex_hooks')
    config = tmp_path / 'hooks.json'
    unrelated = {'matcher': '*', 'hooks': [{'type': 'command', 'command': 'python another_hook.py'}]}
    config.write_text(json.dumps({'hooks': {'PreToolUse': [unrelated]}}), encoding='utf-8')
    installer.install(config)
    installer.install(config)
    data = json.loads(config.read_text(encoding='utf-8'))
    assert data['hooks']['PreToolUse'][0] == unrelated
    assert len(data['hooks']['PreToolUse']) == 2
    assert len(data['hooks']['PostToolUse']) == 1


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows PowerShell launcher regression')
def test_windows_hook_launcher_reaches_python_and_returns_explicit_denial():
    installer = module('install_codex_hooks')
    command = installer._definition(SENSOR / 'hook.py')['hooks'][0]['commandWindows']
    shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    event = {'hook_event_name': 'PreToolUse', 'session_id': 'launcher-regression',
             'tool_use_id': 'read', 'tool_name': 'Bash', 'cwd': str(SENSOR.parent),
             'tool_input': {'command': 'echo harmless'}}
    # No live audit pollution: an unavailable local endpoint must produce a denial.
    result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', command],
        input=json.dumps(event), text=True, encoding='utf-8', capture_output=True,
        env=dict(os.environ, AIRLOCK_URL='http://127.0.0.1:1'), timeout=15)
    assert result.returncode == 0, result.stderr
    verdict = json.loads(result.stdout)
    assert verdict['hookSpecificOutput']['permissionDecision'] == 'deny'
    assert 'fail_closed' in verdict['systemMessage']
