"""Managed API authorization and session binding, using real HTTP requests."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
import service
from engine import Brain


def test_sensor_cannot_administer_or_spoof_session(monkeypatch):
    b=Brain()
    b.configure_session('managed',workspace_root='/work',workspace_id='project',repository_origin='cloned-repo',strict=True)
    for key,value in [('BRAIN',b),('ADMIN_TOKEN','operator-only'),('SENSOR_TOKEN','sensor-only'),('MANAGED_SESSION','managed')]:
        monkeypatch.setattr(service,key,value)
    server=ThreadingHTTPServer(('127.0.0.1',0),service._Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    def call(path,token,data):
        req=urllib.request.Request(f'http://127.0.0.1:{server.server_port}{path}',data=json.dumps(data).encode(),
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        return json.load(urllib.request.urlopen(req))
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            call('/kill','sensor-only',{'session_id':'managed'})
        assert error.value.code==401
        with pytest.raises(urllib.error.HTTPError) as error:
            call('/decide','sensor-only',dict(session_id='spoofed',tool_use_id='read',op='ReadFile',target='/work/README.md'))
        assert error.value.code==403
        verdict=call('/decide','sensor-only',dict(session_id='managed',tool_use_id='read',op='ReadFile',target='/work/README.md',origin='user'))
        assert verdict['decision']=='allow'
        assert call('/complete','sensor-only',dict(session_id='managed',tool_use_id='read',success=True,exposure='exposed'))['ok']
        assert b.store.get_entries('managed')[0].labels.effective_trust.value=='untrusted'
        call('/kill','operator-only',{'session_id':'managed'})
        assert b._is_killed('managed')
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
