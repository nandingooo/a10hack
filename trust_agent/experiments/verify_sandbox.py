"""Verify the live managed boundary and STOP; no LLM invocation required."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import airlock


def verify(session,terminate=False):
    manifest=airlock.load(session)
    source=r'''
import json,os,socket,urllib.request,urllib.error
checks={}
try:
    socket.create_connection(('1.1.1.1',80),timeout=2).close()
    checks['direct_public_network_blocked']=False
except OSError:
    checks['direct_public_network_blocked']=True
try:
    socket.create_connection(('host.docker.internal',8797),timeout=2).close()
    checks['host_control_network_blocked']=False
except OSError:
    checks['host_control_network_blocked']=True
try:
    open('/etc/claude-code/managed-settings.json','w').write('{}')
    checks['managed_settings_protected']=False
except OSError:
    checks['managed_settings_protected']=True
try:
    request=urllib.request.Request('http://gateway:8787/kill',data=json.dumps({'session_id':os.environ['AIRLOCK_SESSION']}).encode(),headers={'Authorization':'Bearer '+os.environ['AIRLOCK_SENSOR_TOKEN']})
    urllib.request.urlopen(request)
    checks['sensor_cannot_kill_or_administer']=False
except urllib.error.HTTPError as error:
    checks['sensor_cannot_kill_or_administer']=error.code==401
try:
    urllib.request.urlopen('http://github.com',timeout=15)
    checks['proxy_blocks_after_secret_context']=False
except urllib.error.HTTPError as error:
    checks['proxy_blocks_after_secret_context']=error.code==403 and b'TrustAgent' in error.read()
print(json.dumps(checks))
assert all(checks.values()),checks
'''
    result=airlock.compose(manifest,'exec','--no-TTY','agent','python3','-c',source)
    checks=json.loads(result)
    if terminate:
        airlock.stop(manifest)
        checks['agent_terminated']=not airlock.compose(manifest,'ps','--status','running','--quiet','agent').strip()
        checks['gateway_and_connections_terminated']=not airlock.compose(manifest,'ps','--status','running','--quiet','gateway').strip()
        assert all(checks.values())
    output=Path(manifest['directory'])/'verification.json'
    output.write_text(json.dumps(checks,indent=2))
    print(json.dumps(checks,indent=2))
    return checks


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session')
    parser.add_argument('--stop',action='store_true')
    args=parser.parse_args()
    verify(args.session,args.stop)
