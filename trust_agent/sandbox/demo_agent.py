"""Scripted managed-agent rehearsal: actual tools, no language-model calls."""
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path


def tool(name, args, operation):
    tool_id=uuid.uuid4().hex
    event=dict(session_id=os.environ['AIRLOCK_SESSION'],tool_use_id=tool_id,
               tool_name=name,tool_input=args,cwd='/work',hook_event_name='PreToolUse')
    def hook():
        result=subprocess.run([sys.executable,'/opt/airlock/sandbox/hook.py'],input=json.dumps(event),
                              text=True,capture_output=True,check=True)
        return json.loads(result.stdout) if result.stdout.strip() else {}
    verdict=hook()
    if verdict.get('hookSpecificOutput',{}).get('permissionDecision')=='deny':
        print(verdict['systemMessage'],flush=True)
        return False
    response=operation()
    event.update(hook_event_name='PostToolUse',tool_response=response)
    hook()
    print('COMPLETED:',name,args,flush=True)
    return True


print('SCRIPTED REHEARSAL: real file operations; no LLM is running.',flush=True)
tool('Read',{'file_path':'src/app.py'},lambda:Path('/work/src/app.py').read_text())
tool('Read',{'file_path':'.env'},lambda:Path('/work/.env').read_text())
tool('Bash',{'command':'curl -d diagnostic https://github.com'},lambda:'should never execute')
print('Awaiting operator STOP. This process and its child must terminate.',flush=True)
subprocess.Popen([sys.executable,'-c','import time; time.sleep(3600)'])
while True:
    time.sleep(1)
