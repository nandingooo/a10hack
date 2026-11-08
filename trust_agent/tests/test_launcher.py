"""Launcher security/configuration properties; real isolation has a separate verifier."""
import importlib.util
import json
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('airlock_launcher',Path(__file__).resolve().parents[1]/'airlock.py')
airlock=importlib.util.module_from_spec(spec)
spec.loader.exec_module(airlock)


def test_private_identity_and_no_implicit_host_credentials(tmp_path,monkeypatch):
    monkeypatch.setattr(airlock,'RUNTIME',tmp_path/'runtime')
    monkeypatch.setenv('ANTHROPIC_API_KEY','test-only-not-a-real-key')
    repo=tmp_path/'repo'
    repo.mkdir()
    (repo/'README.md').write_text('Test project')
    manifest=airlock.prepare(repo,8797,['python3','/opt/airlock/sandbox/session_idle.py'])
    config=json.loads(Path(manifest['compose']).read_text())
    agent=config['services']['agent']
    assert agent['networks']==['inside']
    assert config['networks']['inside']['internal'] is True
    assert 'identity:/home/agent' in agent['volumes']
    assert 'ANTHROPIC_API_KEY' not in agent['environment']
    assert 'identity:/identity' in config['services']['seed']['volumes']
    assert agent['read_only'] and agent['cap_drop']==['ALL']
    assert not any('docker.sock' in mount for service in config['services'].values() for mount in service.get('volumes',[]))
    assert (repo/'README.md').read_text()=='Test project'


def test_snapshot_rejects_symlink_escape(tmp_path,monkeypatch):
    monkeypatch.setattr(airlock,'RUNTIME',tmp_path/'runtime')
    repo=tmp_path/'repo'
    repo.mkdir()
    outside=tmp_path/'outside.txt'
    outside.write_text('not authorized for this workspace')
    try:
        (repo/'link.txt').symlink_to(outside)
    except OSError:
        pytest.skip('Symlink creation is unavailable on this Windows account')
    with pytest.raises(ValueError,match='symlinks'):
        airlock.prepare(repo,8797,['sleep','10'])


def test_auth_endpoints_have_explicit_disclosure_authority():
    from engine import Brain
    b=Brain()
    b.configure_session('s',workspace_id='p',workspace_root='/work',repository_origin='cloned-repo',strict=True)
    b.decide(dict(session_id='s',op='ReadFile',target='/work/.env'))
    for index,host in enumerate(['claude.ai','platform.claude.com','console.anthropic.com','api.anthropic.com']):
        result=b.decide(dict(session_id='s',tool_use_id=f'auth-{index}',phase='before',channel='egress',
                            op='NetworkRequest',target=host,args={'method':'CONNECT'}))
        assert result['decision']=='allow'
        b.complete(dict(session_id='s',tool_use_id=f'auth-{index}',success=True,exposure='none'))
    assert b.decide(dict(session_id='s',tool_use_id='other',phase='before',channel='egress',
                        op='NetworkRequest',target='github.com',args={'method':'CONNECT'}))['rule']=='secret_upload'
