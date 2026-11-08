"""Typed requests enforce scoped URLs while preserving confidentiality restrictions."""
from dataclasses import replace
import socket

from engine import Brain
from mediated_network import perform


def test_scoped_request_cannot_contact_disallowed_destination(monkeypatch):
    b=Brain()
    b.configure_session('s',workspace_root='/repo',workspace_id='p',repository_origin='workspace',strict=True,
        network_capabilities=[{'host':'github.com','path_prefix':'/org/repo','methods':['POST']}])
    def forbidden(*args,**kwargs):
        raise AssertionError('Policy denial must happen before DNS/network access')
    monkeypatch.setattr(socket,'getaddrinfo',forbidden)
    result=perform(b,dict(session_id='s',tool_use_id='send',target='https://github.com/other/repo',args={'method':'POST','body':'public'}))
    assert result['rule']=='task_boundary'


def test_typed_request_cannot_send_secret_to_public_scope(monkeypatch):
    b=Brain()
    b.configure_session('s',workspace_root='/repo',workspace_id='p',repository_origin='workspace',strict=True,
        network_capabilities=[{'host':'github.com','path_prefix':'/org/repo','methods':['POST']}])
    b.decide(dict(session_id='s',op='ReadFile',target='/repo/.env'))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError('Should not resolve')))
    assert perform(b,dict(session_id='s',tool_use_id='send',target='https://github.com/org/repo',args={'method':'POST','body':'test'}))['rule']=='secret_upload'


def test_typed_request_rejects_private_dns_results(monkeypatch):
    b=Brain()
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))])
    result=perform(b,dict(session_id='s',tool_use_id='get',target='https://github.com',args={}))
    assert result['rule']=='network_execution_failed'
    assert 'Private' in result['reason']


def test_typed_error_response_still_records_exposure(monkeypatch):
    import mediated_network
    b=Brain()
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('140.82.114.4',443))])
    class Response:
        status=404
        def read(self,*args): return b'External error document'
        def getheader(self,*args): return 'text/plain'
    class Connection:
        def __init__(self,*args): pass
        def request(self,*args,**kwargs): pass
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(mediated_network,'PinnedHTTPS',Connection)
    result=perform(b,dict(session_id='s',tool_use_id='get',target='https://github.com',args={}))
    assert result['status']==404
    entry=b.store.get_entries('s')[0]
    assert entry.metadata['execution_status']=='failed'
    assert entry.metadata['exposure_status']=='exposed'
    assert entry.labels.effective_trust.value=='untrusted'
