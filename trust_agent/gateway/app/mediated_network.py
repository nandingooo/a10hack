"""Execute a fully modeled HTTP request after guard authorization, without tunnels."""
import base64
import hashlib
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, port):
        super().__init__(host,port,timeout=15,context=ssl.create_default_context())
        self.address=address

    def connect(self):
        raw=socket.create_connection((self.address,self.port),timeout=self.timeout)
        self.sock=self._context.wrap_socket(raw,server_hostname=self.host)


def perform(brain,request):
    """The broker owns execution and completion; caller-reported success is unused."""
    args=request.get('args',{})
    if not isinstance(args,dict) or not isinstance(request.get('target'),str):
        return {'decision':'block','rule':'invalid_request','reason':'URL and arguments required'}
    parsed=urlsplit(request['target'])
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return {'decision':'block','rule':'invalid_url','reason':'Absolute HTTP(S) URL without credentials or fragment required'}
    req=dict(request,phase='before',op='NetworkRequest',channel='egress')
    verdict=brain.decide(req)
    if verdict['decision']!='allow':
        return verdict
    try:
        port=parsed.port or (443 if parsed.scheme=='https' else 80)
        if port not in (80,443): raise ValueError('Nonstandard destination port')
        addresses=socket.getaddrinfo(parsed.hostname,port,type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError('Private, loopback and link-local destinations are prohibited')
        body=args.get('body','')
        if not isinstance(body,str): raise ValueError('Body must be text')
        body=body.encode()
        if len(body)>65536: raise ValueError('Request exceeds inspection limit')
        method=str(args.get('method','GET')).upper()
        if method not in ('GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'):
            raise ValueError('Unsupported request method')
        headers=args.get('headers',{})
        if not isinstance(headers,dict): raise ValueError('Headers must be an object')
        denied={'host','connection','proxy-authorization','transfer-encoding','content-length','upgrade'}
        headers={str(k):str(v) for k,v in headers.items() if k.lower() not in denied}
        address=addresses[0][4][0]
        connection=PinnedHTTPS(parsed.hostname,address,port) if parsed.scheme=='https' else http.client.HTTPConnection(address,port,timeout=15)
        headers['Host']=parsed.netloc
        connection.request(method,(parsed.path or '/')+('?' + parsed.query if parsed.query else ''),body=body or None,headers=headers)
        response=connection.getresponse()
        data=response.read(2*1024*1024+1)
        if len(data)>2*1024*1024: raise ValueError('Response exceeds buffer limit')
        # A response body can expose information even for HTTP failure statuses.
        brain.complete(dict(session_id=req['session_id'],tool_use_id=req['tool_use_id'],
            success=response.status<400,exposure='exposed',output_digest=hashlib.sha256(data).hexdigest()))
        result=dict(verdict,status=response.status,body_base64=base64.b64encode(data).decode(),
                    content_type=response.getheader('Content-Type','application/octet-stream'))
        connection.close()
        return result
    except Exception as exc:
        brain.complete(dict(session_id=req['session_id'],tool_use_id=req['tool_use_id'],success=False,exposure='unknown'))
        return {'decision':'block','rule':'network_execution_failed','reason':str(exc)}
