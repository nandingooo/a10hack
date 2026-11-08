"""TrustAgent egress proxy -- inline network-layer enforcement (Sysdig-style).

A forward HTTP/HTTPS proxy that asks the TrustAgent decision service BEFORE any
outbound connection is allowed. It enforces at the NETWORK layer, independent of
the coding agent: it blocks a destination even for traffic the agent's own hook
never saw -- a `bash curl`, an obfuscated command, or anything the agent would
not emit as a tool call. Denied destinations get HTTP 403; allowed ones pass.

This is the Sysdig/Falco analogy: enforce below the application, so cooperation
of the app is irrelevant. (The PreToolUse hook is the in-agent layer; this is
the runtime layer underneath it -- defense in depth.)

Run:  python sandbox/egress/proxy.py --port 8080 [--session <id>]
Test: curl -x http://127.0.0.1:8080 http://example.com     # blocked (egress_allowlist)
      curl -x http://127.0.0.1:8080 https://example.com    # blocked at CONNECT
      curl -x http://127.0.0.1:8080 https://github.com     # allowed (approved host)
Env:  AIRLOCK_URL (default http://127.0.0.1:8787), AIRLOCK_SESSION
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DECIDE_URL = os.environ.get("AIRLOCK_URL", "http://127.0.0.1:8787") + "/decide"
SESSION = os.environ.get("AIRLOCK_SESSION", "egress-demo")


def ask(host: str, body: str = "") -> dict:
    req = {"session_id": SESSION, "channel": "egress", "op": "NetworkRequest",
           "target": host, "args": {"host": host, "body": body[:4096]}}
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(DECIDE_URL, data=json.dumps(req).encode(),
                                   headers={"Content-Type": "application/json"}), timeout=5)
        return json.loads(r.read())
    except Exception as e:  # service down -> fail closed
        return {"decision": "block", "rule": "fail_closed",
                "reason": f"decision service unreachable: {e}", "confidence": 1.0}


def _relay(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _deny(self, host: str, v: dict) -> None:
        print(f"[egress] {host:30s} -> BLOCK ({v.get('rule')})", flush=True)
        body = json.dumps({"TrustAgent": "BLOCKED", **v}).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):   # HTTPS tunnels
        host = self.path.rsplit(":", 1)[0]
        port = int(self.path.rsplit(":", 1)[1]) if ":" in self.path else 443
        v = ask(host)
        if v["decision"] in ("block", "stop", "ask"):
            return self._deny(host, v)
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            self.send_error(502)
            return
        print(f"[egress] {host:30s} -> ALLOW (tunnel)", flush=True)
        self.send_response(200, "Connection Established")
        self.end_headers()
        client = self.connection
        threading.Thread(target=_relay, args=(upstream, client), daemon=True).start()
        _relay(client, upstream)

    def _http(self):   # plain HTTP (absolute-form proxy request)
        host = urlsplit(self.path).hostname
        if not host:
            self.send_error(400)
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        v = ask(host, body.decode("utf-8", "replace"))
        if v["decision"] in ("block", "stop", "ask"):
            return self._deny(host, v)
        try:
            req = urllib.request.Request(self.path, data=body or None, method=self.command)
            for k, val in self.headers.items():
                if k.lower() not in ("proxy-connection", "connection", "content-length", "host"):
                    req.add_header(k, val)
            resp = urllib.request.urlopen(req, timeout=15)
            data = resp.read()
            print(f"[egress] {host:30s} -> ALLOW (forward)", flush=True)
            self.send_response(resp.status)
            for k, val in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, val)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(502, str(e))

    do_GET = _http
    do_POST = _http
    do_PUT = _http
    do_DELETE = _http
    do_HEAD = _http


def main(argv=None):
    global SESSION
    ap = argparse.ArgumentParser(description="TrustAgent egress proxy")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--session", default=SESSION)
    a = ap.parse_args(argv)
    SESSION = a.session
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Proxy)
    print(f"TrustAgent egress proxy on http://127.0.0.1:{a.port} (session={SESSION}) "
          f"-> decides via {DECIDE_URL}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
