"""Loopback operator UI. Session sensor credentials are never sent to the browser."""
import hmac
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import airlock

STATIC=Path(__file__).with_name('static')


def run_view(manifest):
    try:
        running=airlock.docker('inspect',manifest['project']+'-agent-1','--format','{{.State.Running}}',timeout=5).strip()=='true'
    except Exception:
        return {'session_id':manifest['session_id'],'status':'UNKNOWN',
                'workspace_id':manifest['workspace_id'],'port':manifest['port']}
    return {'session_id':manifest['session_id'],'status':'RUNNING' if running else 'STOPPED',
            'workspace_id':manifest['workspace_id'],'port':manifest['port']}


def serve(port=8798,token=None):
    token=token or secrets.token_urlsafe(32)
    airlock.RUNTIME.mkdir(exist_ok=True)
    key_path=airlock.RUNTIME/'operator-token'
    key_path.write_text(token)
    if sys.platform!='win32': key_path.chmod(0o600)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send(self,code,data,mime='application/json'):
            body=json.dumps(data).encode() if mime=='application/json' else data
            self.send_response(code)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
        def authorized(self):
            host=self.headers.get('Host','')
            expected={f'127.0.0.1:{port}',f'localhost:{port}'}
            origin=self.headers.get('Origin')
            return host in expected and (not origin or origin in {'http://'+h for h in expected}) and hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token)
        def do_GET(self):
            path=urlsplit(self.path).path
            if path.startswith('/api/'):
                if not self.authorized(): return self.send(401,{'error':'Connect with the local operator access key'})
                try:
                    if path=='/api/runs':
                        manifests=[airlock.load(p.parent.name) for p in airlock.RUNTIME.glob('*/run.json')]
                        return self.send(200,{'runs':[run_view(m) for m in reversed(manifests)]})
                    parts=path.split('/')
                    manifest=airlock.load(parts[3])
                    if parts[4]=='events':
                        after=max(0,int(parse_qs(urlsplit(self.path).query).get('after',['0'])[0]))
                        try: data=airlock.api(manifest,f'/events?after={after}')
                        except Exception:
                            archived=json.loads(Path(manifest['directory'],'audit.json').read_text())
                            data={'events':[e for e in archived['events'] if e['seq']>after][:1000]}
                        return self.send(200,data)
                    if parts[4]=='entries':
                        try: data=airlock.api(manifest,'/entries')
                        except Exception: data=json.loads(Path(manifest['directory'],'entries.json').read_text())
                        return self.send(200,data)
                except Exception as exc:
                    return self.send(503,{'error':str(exc)})
                return self.send(404,{'error':'Unknown endpoint'})
            files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
            if path not in files: return self.send(404,b'Not found','text/plain')
            name,mime=files[path]
            return self.send(200,(STATIC/name).read_bytes(),mime)
        def do_POST(self):
            if not self.authorized(): return self.send(401,{'error':'Operator authentication required'})
            parts=urlsplit(self.path).path.split('/')
            if len(parts)!=5 or parts[:3]!=['','api','runs'] or parts[4]!='stop':
                return self.send(404,{'error':'Unknown endpoint'})
            try:
                manifest=airlock.load(parts[3])
                airlock.stop(manifest)
                state=run_view(manifest)
                if state['status']!='STOPPED': raise RuntimeError('Container is still running; STOP is not verified')
                return self.send(200,state)
            except Exception as exc:
                return self.send(503,{'error':str(exc)})
    print(f'TrustAgent operator UI: http://127.0.0.1:{port}/#access={token}',flush=True)
    ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8798)
    args=parser.parse_args()
    serve(args.port)
