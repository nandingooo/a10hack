"""Security properties of exposure tracking, not just execution success."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from engine import Brain
from provenance import Policy, SqliteStore


def request(brain, tool, op='ReadFile', target='.env', session='a', **args):
    return brain.decide(dict(session_id=session, tool_use_id=tool, phase='before',
                             op=op, target=target, cwd='/repo', args=args))


def result(brain, tool, success=True, exposure='exposed', session='a'):
    return brain.complete(dict(session_id=session, tool_use_id=tool, success=success, exposure=exposure))


@pytest.fixture(params=['memory','sqlite'])
def brain(request):
    store = SqliteStore(':memory:') if request.param == 'sqlite' else None
    b = Brain(store)
    for sid in ('a','b'):
        b.configure_session(sid, workspace_id='same-repository',workspace_root='/repo',repository_origin='cloned-repo')
    yield b
    if store:
        store.close()


def test_partial_failure_still_exposes_secret(brain):
    request(brain,'read')
    assert result(brain,'read',False,'exposed')['ok']
    verdict = request(brain,'upload','NetworkRequest','github.com',method='POST')
    assert verdict['rule'] == 'secret_upload'
    assert verdict['evidence'][0]['execution_status'] == 'failed'
    assert verdict['evidence'][0]['exposure_status'] == 'exposed'


def test_unknown_failure_is_conservatively_labeled(brain):
    request(brain,'read')
    result(brain,'read',False,'unknown')
    assert request(brain,'upload','NetworkRequest','github.com',method='POST')['rule'] == 'secret_upload'


def test_unresolved_read_blocks_sink_until_reconciled(brain):
    # Exposure reconciliation is enforced only in the strict (isolated) sandbox;
    # hook-mode must not false-block on a lagging completion (parallel tool calls).
    brain.configure_session('strictsess', workspace_id='same-repository', workspace_root='/repo',
                            repository_origin='cloned-repo', strict=True)
    request(brain,'read',session='strictsess')
    assert request(brain,'write','WriteFile','output.txt',session='strictsess')['rule'] == 'unresolved_exposure'
    result(brain,'read',False,'none',session='strictsess')
    assert request(brain,'write2','WriteFile','output.txt',session='strictsess')['decision'] == 'allow'


def test_hookmode_does_not_block_on_unresolved_exposure(brain):
    # Regression: a non-strict (hook-mode) session must allow consequential work
    # even while a prior read's completion is still pending.
    request(brain,'read')
    assert request(brain,'write','WriteFile','output.txt')['decision'] == 'allow'


def test_root_readme_is_untrusted(brain):
    request(brain,'read','ReadFile','README.md')
    result(brain,'read')
    assert brain.store.get_entries('a')[0].labels.effective_trust.value == 'untrusted'


def test_derived_artifact_keeps_labels_across_sessions_and_copy(brain):
    request(brain,'read')
    result(brain,'read')
    request(brain,'write','WriteFile','notes.txt')
    result(brain,'write')
    request(brain,'copy','CopyFile','src/report.txt',session='b',source='notes.txt')
    result(brain,'copy',session='b')
    request(brain,'reread','ReadFile','src/report.txt',session='b')
    result(brain,'reread',session='b')
    v = request(brain,'upload','NetworkRequest','github.com',session='b',method='POST')
    assert v['rule'] == 'secret_upload'
    assert any(e.get('classification_reason') == 'inherited_artifact' for e in v['evidence'])


def test_url_and_headers_are_outbound_channels(brain):
    request(brain,'read')
    result(brain,'read')
    assert request(brain,'query','NetworkRequest','https://github.com/?data=test')['rule'] == 'secret_upload'
    assert request(brain,'header','NetworkRequest','github.com',headers={'X-Data':'test'})['rule'] == 'secret_upload'


def test_conflicting_result_retry_rejected(brain):
    request(brain,'read')
    result(brain,'read')
    assert result(brain,'read',False,'none')['rule'] == 'result_conflict'


def test_concurrent_completions_append_once(brain):
    request(brain,'read')
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: result(brain,'read'),range(8)))
    assert all(v['ok'] for v in results)
    assert len(brain.store.get_entries('a')) == 1


def test_completion_rollback_is_atomic(tmp_path, monkeypatch):
    store = SqliteStore(tmp_path/'atomic.db')
    b = Brain(store)
    request(b,'read')
    original = b.state.log
    def fail(*args,**kwargs):
        raise RuntimeError('simulated journal failure')
    monkeypatch.setattr(b.state,'log',fail)
    with pytest.raises(RuntimeError):
        result(b,'read')
    assert store.get_entries('a') == []
    monkeypatch.setattr(b.state,'log',original)
    assert result(b,'read')['ok']
    assert len(store.get_entries('a')) == 1
    store.close()


def test_workspace_namespaces_are_isolated(brain):
    brain.configure_session('other',workspace_id='different-repository',workspace_root='/repo',repository_origin='workspace')
    request(brain,'read')
    result(brain,'read')
    request(brain,'write','WriteFile','notes.txt')
    result(brain,'write')
    request(brain,'read','ReadFile','notes.txt',session='other')
    result(brain,'read',session='other')
    assert request(brain,'upload','NetworkRequest','github.com',session='other',method='POST')['decision'] == 'allow'


def test_operator_task_scope_and_secret_policy_are_independent():
    b=Brain()
    b.configure_session('a',workspace_id='project',workspace_root='/repo',repository_origin='workspace',strict=True,
        network_capabilities=[dict(host='github.com',path_prefix='/org/project',methods=['POST'])])
    assert request(b,'other','NetworkRequest','https://github.com/other/project',method='POST')['rule']=='task_boundary'
    assert request(b,'allowed','NetworkRequest','https://github.com/org/project/report',method='POST')['decision']=='allow'
    result(b,'allowed',exposure='none')
    request(b,'secret')
    result(b,'secret')
    assert request(b,'secret-send','NetworkRequest','https://github.com/org/project/report',method='POST')['rule']=='secret_upload'


def test_move_preserves_labels_with_explicit_operator_authority(brain):
    brain.configure_session('mover',workspace_id='same-repository',workspace_root='/repo',repository_origin='workspace',allowed_operations=['MoveFile'])
    request(brain,'read')
    result(brain,'read')
    request(brain,'write','WriteFile','notes.txt')
    result(brain,'write')
    assert request(brain,'move','MoveFile','src/renamed.txt',session='mover',source='notes.txt')['decision']=='allow'
    result(brain,'move',session='mover')
    request(brain,'read','ReadFile','src/renamed.txt',session='mover')
    result(brain,'read',session='mover')
    assert request(brain,'send','NetworkRequest','github.com',session='mover',method='POST')['rule']=='secret_upload'


def test_denial_acknowledgment_is_idempotent(brain):
    request(brain,'blocked','NetworkRequest','unapproved.example')
    assert brain.acknowledge_denial({'session_id':'a','tool_use_id':'blocked'})['ok']
    assert brain.acknowledge_denial({'session_id':'a','tool_use_id':'blocked'})['ok']
    acknowledgments=[e for e in brain.events('a') if e['type']=='enforcement']
    assert len(acknowledgments)==1
    assert acknowledgments[0]['sensor_reported'] is True


def test_shell_cannot_disclaim_private_runtime_access(tmp_path):
    b=Brain()
    b.configure_session('a',workspace_root=str(tmp_path),workspace_id='p',repository_origin='workspace',strict=True,ambient_secret=True)
    b.decide(dict(session_id='a',phase='before',tool_use_id='shell',op='RunCommand',target='python script.py',args={}))
    assert result(b,'shell',exposure='none')['ok']
    assert request(b,'send','NetworkRequest','github.com',method='POST')['rule']=='secret_upload'
