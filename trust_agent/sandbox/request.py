"""Typed gateway request helper for scoped HTTP(S) operations in the sandbox."""
import argparse
import base64
import json
import os
import sys
import urllib.request
import uuid

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('url')
parser.add_argument('--method',default='GET')
parser.add_argument('--body',default='')
args=parser.parse_args()
request=urllib.request.Request(os.environ['AIRLOCK_URL']+'/network',
    data=json.dumps(dict(session_id=os.environ['AIRLOCK_SESSION'],tool_use_id=uuid.uuid4().hex,
        target=args.url,args={'method':args.method,'body':args.body})).encode(),
    headers={'Content-Type':'application/json','Authorization':'Bearer '+os.environ['AIRLOCK_SENSOR_TOKEN']})
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=30) as response:
    result=json.load(response)
if result.get('decision')!='allow':
    print(f"TrustAgent BLOCKED [{result.get('rule')}]: {result.get('reason')}",file=sys.stderr)
    raise SystemExit(2)
sys.stdout.buffer.write(base64.b64decode(result['body_base64']))
raise SystemExit(0 if result['status']<400 else 1)
