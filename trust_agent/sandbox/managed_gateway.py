"""One isolated session's guard and egress gateway. No Docker socket access."""
import os
import json
import sys
import threading
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'gateway/app'))
sys.path.insert(0,str(Path(__file__).resolve().parent/'egress'))
import service
import proxy
from engine import Brain
from provenance import Policy, SqliteStore
from http.server import ThreadingHTTPServer


def main():
    session = os.environ['AIRLOCK_SESSION']
    service.BRAIN = Brain(SqliteStore('/state/guard.db'),Policy.load('/policy/labels.yaml'))
    service.BRAIN.configure_session(session, allow_strengthening=True, workspace_root='/work',
        workspace_id=os.environ['AIRLOCK_WORKSPACE_ID'], repository_origin=os.environ.get('AIRLOCK_REPOSITORY_ORIGIN','cloned-repo'),strict=True,
        network_capabilities=json.loads(os.environ.get('AIRLOCK_NETWORK_CAPABILITIES','[]')),
        ambient_secret=True)
    service.ADMIN_TOKEN = os.environ['AIRLOCK_ADMIN_TOKEN']
    service.SENSOR_TOKEN = os.environ['AIRLOCK_SENSOR_TOKEN']
    service.MANAGED_SESSION = session
    proxy.SESSION = session
    proxy.DECIDE_URL = 'http://127.0.0.1:8787/decide'
    proxy.SENSOR_TOKEN = service.SENSOR_TOKEN
    api = ThreadingHTTPServer(('0.0.0.0',8787),service._Handler)
    threading.Thread(target=api.serve_forever,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',8080),proxy.Proxy).serve_forever()


if __name__ == '__main__':
    main()
