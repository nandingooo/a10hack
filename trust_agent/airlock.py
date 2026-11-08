"""Managed sandbox CLI. Run `python trust_agent/airlock.py --help`."""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / '.runtime'


def docker(*args, **kwargs):
    return subprocess.run(['docker',*args],check=True,text=True,capture_output=True,timeout=kwargs.pop('timeout',120),**kwargs).stdout


def api(manifest, path, data=None):
    request = urllib.request.Request(f"http://127.0.0.1:{manifest['port']}{path}",
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Authorization':'Bearer '+manifest['admin_token'],'Content-Type':'application/json'})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=3) as response:
        return json.load(response)


def load(session):
    if not session or any(c not in 'abcdef0123456789' for c in session) or len(session)!=32:
        raise ValueError('Invalid session ID')
    path = RUNTIME/session/'run.json'
    value=json.loads(path.read_text())
    if value['session_id']!=session:
        raise ValueError('Manifest identity mismatch')
    return value


def compose(manifest,*args,**kwargs):
    return docker('compose','--project-name',manifest['project'],'--file',manifest['compose'],*args,**kwargs)


def all_events(manifest):
    events=[]
    cursor=0
    while True:
        page=api(manifest,f'/events?after={cursor}')['events']
        events.extend(page)
        if len(page)<1000:
            return {'events':events}
        next_cursor=page[-1]['seq']
        if next_cursor<=cursor:
            raise RuntimeError('Event pagination did not advance')
        cursor=next_cursor


def stop(manifest):
    # Revocation is attempted first; process termination proceeds even if guard is down.
    try:
        api(manifest,'/kill',{'session_id':manifest['session_id']})
    except Exception:
        pass
    for endpoint, filename in (('/events','audit.json'),('/entries','entries.json')):
        try:
            data=all_events(manifest) if endpoint=='/events' else api(manifest,endpoint)
            Path(manifest['directory'],filename).write_text(json.dumps(data))
        except Exception:
            pass
    compose(manifest,'stop','--timeout','0','agent','gateway')
    for service in ('agent','gateway'):
        ids=compose(manifest,'ps','--status','running','--quiet',service).strip()
        if ids:
            raise RuntimeError(f'{service} still running; termination is not verified')
    manifest['status']='STOPPED'
    Path(manifest['directory'],'run.json').write_text(json.dumps(manifest,indent=2))


def prepare(repo,port,command,capabilities=None,rehearsal=None):
    repo=Path(repo).resolve(strict=True)
    if not repo.is_dir() or repo == ROOT or (ROOT in repo.parents and repo != ROOT/'experiments/live_demo_repo'):
        raise ValueError('Choose a separate project directory or the demo fixture, not the harness source')
    session=uuid.uuid4().hex
    directory=RUNTIME/session
    directory.mkdir(parents=True)
    snapshot=directory/'input'
    # Dereferencing workspace symlinks could expose resources outside the authorized repo.
    for base,dirs,files in os.walk(repo,followlinks=False):
        dirs[:]=[d for d in dirs if d not in ('.git','.claude','node_modules','.venv','__pycache__')]
        for name in dirs+files:
            info = Path(base,name).lstat()
            junction = os.name == 'nt' and info.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
            if stat.S_ISLNK(info.st_mode) or junction:
                raise ValueError('Resolve repository symlinks explicitly before sandbox launch')
    shutil.copytree(repo,snapshot,ignore=shutil.ignore_patterns('.git','.claude','node_modules','.venv','__pycache__'))
    manifest=dict(session_id=session, project='airlock-'+session,port=port,directory=str(directory),
                  compose=str(directory/'compose.json'),admin_token=secrets.token_urlsafe(32),
                  sensor_token=secrets.token_urlsafe(32),workspace_id=hashlib.sha256(str(repo).encode()).hexdigest(),status='PREPARED')
    if rehearsal:
        manifest['rehearsal'] = rehearsal
    shutil.copy2(ROOT/'gateway/policy/labels.yaml',directory/'labels.yaml')
    env={'AIRLOCK_SESSION':session,'AIRLOCK_URL':'http://gateway:8787',
         'AIRLOCK_SENSOR_TOKEN':manifest['sensor_token'],'HTTP_PROXY':'http://gateway:8080',
         'HTTPS_PROXY':'http://gateway:8080','http_proxy':'http://gateway:8080',
         'https_proxy':'http://gateway:8080','NO_PROXY':'gateway,127.0.0.1,localhost',
         'no_proxy':'gateway,127.0.0.1,localhost','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
    spec={'services':{
      'seed':{'image':'trustagent-agent:local','build':{'context':str(ROOT),'dockerfile':'sandbox/Dockerfile.agent'},
              'user':'0:0','network_mode':'none','read_only':True,'cap_drop':['ALL'],
              'cap_add':['CHOWN','DAC_OVERRIDE','FOWNER'],
              'volumes':[f'{snapshot.as_posix()}:/input:ro','workspace:/work','identity:/identity'],
              'command':['python3','/opt/airlock/sandbox/seed_workspace.py']},
      'gateway':{'image':'trustagent-gateway:local','build':{'context':str(ROOT),'dockerfile':'sandbox/Dockerfile.gateway'},
              'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
              'networks':['inside','outside'],'ports':[f'127.0.0.1:{port}:8787'],
              'volumes':['state:/state','workspace:/work:ro',f'{(directory/"labels.yaml").as_posix()}:/policy/labels.yaml:ro'],
              'environment':{'AIRLOCK_SESSION':session,'AIRLOCK_WORKSPACE_ID':manifest['workspace_id'],
                    'AIRLOCK_ADMIN_TOKEN':manifest['admin_token'],'AIRLOCK_SENSOR_TOKEN':manifest['sensor_token'],
                    'AIRLOCK_NETWORK_CAPABILITIES':json.dumps(capabilities or [])},
              'tmpfs':['/tmp:rw,noexec,nosuid,size=64m']},
      'agent':{'image':'trustagent-agent:local','depends_on':{'seed':{'condition':'service_completed_successfully'}},
              'init':True,'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
              'pids_limit':128,'mem_limit':'1g','networks':['inside'],'environment':env,
              'volumes':['workspace:/work','identity:/home/agent'],
              'tmpfs':['/tmp:rw,nosuid,size=128m'],
              'command':command}},
      'networks':{'inside':{'internal':True,'driver_opts':{'com.docker.network.bridge.gateway_mode_ipv4':'isolated'}},'outside':{}},
      'volumes':{'workspace':{},'state':{},'identity':{}}}
    # Authentication is performed by the unmodified Claude CLI in its private
    # session volume. Never import host credentials or implicitly select an API key.
    Path(manifest['compose']).write_text(json.dumps(spec,indent=2))
    Path(directory/'run.json').write_text(json.dumps(manifest,indent=2))
    if os.name!='nt':
        directory.chmod(0o700)
        Path(directory/'run.json').chmod(0o600)
        Path(manifest['compose']).chmod(0o600)
    return manifest


def supervise(manifest):
    print('Session:',manifest['session_id'],flush=True)
    print('Guard:',f"http://127.0.0.1:{manifest['port']}",flush=True)
    try:
        while True:
            ids=compose(manifest,'ps','--status','running','--quiet','agent').strip()
            if not ids:
                print('Agent process exited.',flush=True)
                stop(manifest)
                return
            try:
                if api(manifest,'/status')['status']=='KILLED':
                    stop(manifest)
                    print('STOP verified: agent and gateway terminated.',flush=True)
                    return
            except Exception:
                stop(manifest)
                raise RuntimeError('Guard unavailable; managed run terminated')
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop(manifest)


def main():
    from sandbox.demo_agent import REHEARSALS

    parser=argparse.ArgumentParser(description=__doc__)
    subs=parser.add_subparsers(dest='action',required=True)
    run=subs.add_parser('run')
    run.add_argument('--repo',required=True)
    run.add_argument('--port',type=int,default=8787)
    run.add_argument('--detach',action='store_true')
    run.add_argument('--rehearsal', choices=REHEARSALS, help='Run a scripted security scenario in the sandbox')
    run.add_argument('--allow-public-upload',action='append',default=[],metavar='HTTPS_URL',help='Authorize POST/PUT/PATCH to this exact host and path subtree; secret context remains prohibited')
    run.add_argument('command',nargs=argparse.REMAINDER)
    for verb in ('stop','logs','status','supervise'):
        subs.add_parser(verb).add_argument('session')
    for verb in ('login','chat','auth-status'):
        subs.add_parser(verb).add_argument('session')
    args=parser.parse_args()
    if args.action=='run':
        if args.rehearsal and args.command:
            run.error('--rehearsal cannot be combined with a custom command')
        docker('info','--format','{{.ServerVersion}}',timeout=15)
        command=args.command or ['python3','/opt/airlock/sandbox/session_idle.py']
        if command[0]=='--': command=command[1:]
        if args.rehearsal:
            command = ['python3', '/opt/airlock/sandbox/demo_agent.py', args.rehearsal]
        from urllib.parse import urlsplit
        capabilities=[]
        for url in args.allow_public_upload:
            parsed=urlsplit(url)
            if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
                raise ValueError('Upload scope must be an HTTPS URL without credentials, query or fragment')
            capabilities.append(dict(host=parsed.hostname,path_prefix=parsed.path or '/',methods=['POST','PUT','PATCH']))
        manifest=prepare(args.repo,args.port,command,capabilities,rehearsal=args.rehearsal)
        print('Building managed images...',flush=True)
        compose(manifest,'build',timeout=1200)
        compose(manifest,'up','--detach','gateway',timeout=120)
        for _ in range(40):
            try:
                api(manifest,'/health')
                break
            except Exception:
                time.sleep(0.25)
        else:
            stop(manifest)
            raise RuntimeError('Gateway did not become healthy')
        try:
            compose(manifest,'up','--detach','agent',timeout=120)
        except Exception:
            stop(manifest)
            raise
        manifest['status']='RUNNING'
        Path(manifest['directory'],'run.json').write_text(json.dumps(manifest,indent=2))
        if args.detach:
            log=open(Path(manifest['directory'])/'supervisor.log','a')
            subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'supervise',manifest['session_id']],
                stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0,
                start_new_session=os.name!='nt')
            print('Session:',manifest['session_id'])
        else:
            supervise(manifest)
    else:
        manifest=load(args.session)
        if args.action=='stop': stop(manifest)
        elif args.action=='logs': print(compose(manifest,'logs','--no-color','agent'))
        elif args.action=='status': print(api(manifest,'/status'))
        elif args.action in ('login','chat','auth-status'):
            command={'login':['claude','auth','login'],'chat':['claude'],
                     'auth-status':['claude','auth','status']}[args.action]
            # Inherit the operator's terminal; login codes never enter captured logs.
            cli=['docker','compose','--project-name',manifest['project'],'--file',manifest['compose'],'exec']
            if args.action=='auth-status': cli.append('--no-TTY')
            raise SystemExit(subprocess.call(cli+['agent']+command))
        else: supervise(manifest)


if __name__=='__main__':
    main()
