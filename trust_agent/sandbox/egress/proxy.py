"""Session-bound forward proxy; guard checks are mandatory and fail closed."""
import argparse
import http.client
import ipaddress
import json
import os
import socket
import threading
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DECIDE_URL=os.environ.get('AIRLOCK_URL','http://127.0.0.1:8787')+'/decide'
SESSION=os.environ.get('AIRLOCK_SESSION')
SENSOR_TOKEN=os.environ.get('AIRLOCK_SENSOR_TOKEN','')
ALLOW_PRIVATE_HOSTS=set(filter(None,os.environ.get('AIRLOCK_PRIVATE_FIXTURES','').split(',')))


def call(path,payload):
    req=urllib.request.Request(DECIDE_URL.rsplit('/',1)[0]+path,data=json.dumps(payload).encode(),
        headers={'Content-Type':'application/json','Authorization':'Bearer '+SENSOR_TOKEN})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=5) as response:
        return json.load(response)


def ask(target,body='',method='CONNECT',headers=None):
    tool_id=uuid.uuid4().hex
    try:
        verdict=call('/decide',dict(session_id=SESSION,channel='egress',op='NetworkRequest',target=target,
                    phase='before',tool_use_id=tool_id,args=dict(body=body,method=method,headers=headers or {})))
        if verdict.get('decision') not in ('allow','block','stop','ask'):
            raise ValueError('Invalid guard verdict')
        return dict(verdict,tool_use_id=tool_id)
    except Exception as exc:
        return dict(decision='block',rule='fail_closed',reason=str(exc))


def finish(verdict,success):
    if verdict.get('decision')=='allow':
        try:
            call('/complete',dict(session_id=SESSION,tool_use_id=verdict['tool_use_id'],success=success,
                                 exposure='unknown' if success else 'none'))
        except Exception:
            # Missing completion leaves unresolved state; future sinks fail closed.
            pass


def resolve(host,port):
    if port not in (80,443) and host not in ALLOW_PRIVATE_HOSTS:
        raise ValueError('Only HTTP/HTTPS ports are permitted')
    addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('No destination address')
    if host not in ALLOW_PRIVATE_HOSTS and any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError('Private, loopback and link-local destinations are prohibited')
    return addresses[0][4][0]


def relay(src,dst,check=None):
    try:
        while True:
            data=src.recv(65536)
            if not data:
                break
            if check and not check():
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src,dst):
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass


class Proxy(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass

    def deny(self,verdict):
        if verdict.get('tool_use_id'):
            try:
                call('/enforcement',dict(session_id=SESSION,tool_use_id=verdict['tool_use_id']))
            except Exception:
                pass
        body=json.dumps(dict(TrustAgent='BLOCKED',**verdict)).encode()
        self.send_response(403)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection=True

    def do_CONNECT(self):
        try:
            parsed=urlsplit('//'+self.path)
            host,port=parsed.hostname,parsed.port or 443
            if not host or parsed.username or parsed.password:
                raise ValueError('Invalid CONNECT authority')
            verdict=ask(host,method='CONNECT')
            if verdict['decision']!='allow':
                return self.deny(verdict)
            ip=resolve(host,port)
            upstream=socket.create_connection((ip,port),timeout=10)
        except Exception as exc:
            return self.deny(dict(rule='destination_boundary',decision='block',reason=str(exc)))
        finish(verdict,True) # conservatively mark potential incoming data before exposing the tunnel
        self.send_response(200,'Connection Established')
        self.end_headers()
        def check():
            current=ask(host,method='CONNECT')
            permitted=current['decision']=='allow'
            finish(current,False) # rechecks transfer no new inbound context
            return permitted
        threading.Thread(target=relay,args=(upstream,self.connection),daemon=True).start()
        try:
            relay(self.connection,upstream,check)
        finally:
            upstream.close()
            finish(verdict,True)
            self.close_connection=True

    def _http(self):
        verdict=None
        try:
            parsed=urlsplit(self.path)
            if parsed.scheme!='http' or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError('Absolute HTTP URL required')
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('Chunked request bodies require a modeled sensor')
            length=int(self.headers.get('Content-Length') or 0)
            if length<0 or length>65536:
                raise ValueError('Request body exceeds inspection limit')
            body=self.rfile.read(length)
            headers={k:v for k,v in self.headers.items() if k.lower() not in
                     ('proxy-authorization','proxy-connection','connection','content-length','host','transfer-encoding','upgrade')}
            verdict=ask(self.path,body.decode('utf-8','replace'),self.command,headers)
            if verdict['decision']!='allow':
                return self.deny(verdict)
            ip=resolve(parsed.hostname,parsed.port or 80)
            headers['Host']=parsed.netloc
            conn=http.client.HTTPConnection(ip,parsed.port or 80,timeout=15)
            conn.request(self.command,(parsed.path or '/')+('?' + parsed.query if parsed.query else ''),body=body or None,headers=headers)
            response=conn.getresponse()
            data=response.read(8*1024*1024+1)
            if len(data)>8*1024*1024:
                raise ValueError('Response exceeds buffer limit')
            # Redirects are returned to the client, never followed inside the proxy.
            self.send_response(response.status)
            for k,v in response.getheaders():
                if k.lower() not in ('connection','transfer-encoding','content-length'):
                    self.send_header(k,v)
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Connection','close')
            self.end_headers()
            finish(verdict,True)
            self.wfile.write(data)
            conn.close()
            finish(verdict,True)
        except Exception as exc:
            if verdict: finish(verdict,False)
            self.deny(dict(decision='block',rule='destination_boundary',reason=str(exc)))
        finally:
            self.close_connection=True

    do_GET=_http
    do_POST=_http
    do_PUT=_http
    do_PATCH=_http
    do_DELETE=_http
    do_HEAD=_http
    do_OPTIONS=_http


def main():
    global SESSION
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8080)
    parser.add_argument('--session',default=SESSION)
    args=parser.parse_args()
    SESSION=args.session
    if not SESSION: parser.error('--session required')
    ThreadingHTTPServer(('127.0.0.1',args.port),Proxy).serve_forever()

if __name__=='__main__': main()
