"""AgentAirlock decision service (the persistent gateway "brain").

Holds a GraphStore + Labeler in memory ACROSS hook calls, so `trace_back` sees
the whole session's provenance when an action is evaluated. The PreToolUse hook
is a thin client that POSTs each planned action here and enforces the verdict.

Endpoints (stdlib http.server, no deps):
  POST /decide  {session_id, op, target, origin?, args}  -> {decision, rule, reason, confidence}
  POST /kill    {session_id}                              -> {ok:true}
  GET  /health                                           -> {ok:true}

Run:  python gateway/app/service.py --port 8787
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import secrets
from dataclasses import asdict
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_APP = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _APP not in sys.path:
    sys.path.insert(0, _APP)

from provenance import SqliteStore

from engine import Brain


ADMIN_TOKEN = os.environ.get("AIRLOCK_ADMIN_TOKEN")
SENSOR_TOKEN = os.environ.get("AIRLOCK_SENSOR_TOKEN")
MANAGED_SESSION = os.environ.get("AIRLOCK_SESSION")
BRAIN = Brain()


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self, sensor=False):
        if not ADMIN_TOKEN:
            return True
        value = self.headers.get('Authorization', '')
        tokens = [ADMIN_TOKEN] + ([SENSOR_TOKEN] if sensor and SENSOR_TOKEN else [])
        return any(secrets.compare_digest(value, 'Bearer ' + token) for token in tokens)

    def do_GET(self):
        if self.path != '/health' and not self._authorized():
            self._send(401, {'error':'operator authentication required'})
            return
        if self.path == "/health":
            self._send(200, {"ok": True})
        elif self.path == '/status':
            sid = MANAGED_SESSION
            self._send(200, {'session_id':sid,'status':'KILLED' if sid and BRAIN._is_killed(sid) else 'ACTIVE'})
        elif self.path == '/sessions':
            self._send(200, {'sessions':BRAIN.sessions()})
        elif self.path == '/agents':
            # every session the gateway has seen, incl. hook-mode (un-configured) ones
            self._send(200, {'agents': BRAIN.agents()})
        elif self.path == '/agents':
            self._send(200, {'agents':BRAIN.agents()})
        elif urlsplit(self.path).path == '/entries':
            sid = parse_qs(urlsplit(self.path).query).get('session_id',[MANAGED_SESSION])[0]
            self._send(200, {'entries':[asdict(e) for e in BRAIN.store.get_entries(sid)]})
        elif urlsplit(self.path).path == "/events":
            session = parse_qs(urlsplit(self.path).query).get("session_id", [MANAGED_SESSION])[0]
            self._send(200, {"events": BRAIN.events(session, int(parse_qs(urlsplit(self.path).query).get("after", ["0"])[0]))})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized(sensor=self.path in ('/decide','/complete','/network','/enforcement')):
            self._send(401, {'error':'authentication required'})
            return
        n = int(self.headers.get("Content-Length") or 0)
        if n > 262144:
            self._send(413, {'error':'request too large'})
            return
        raw = self.rfile.read(n) if n else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid JSON"})
            return
        if not isinstance(req, dict):
            self._send(400, {"error": "JSON object required"})
            return
        if MANAGED_SESSION:
            if req.get('session_id') != MANAGED_SESSION:
                self._send(403, {'error':'session scope mismatch'})
                return
            req.pop('origin', None)
        if self.path == '/enforcement':
            self._send(200,BRAIN.acknowledge_denial(req))
        elif self.path == '/network':
            from mediated_network import perform
            self._send(200,perform(BRAIN,req))
        elif self.path == "/complete":
            self._send(200, BRAIN.complete(req))
        elif self.path == "/decide":
            req["phase"] = "before"
            verdict = BRAIN.decide(req)
            print(f"[decide] {str(req.get('op')):14s} {str(req.get('target'))[:60]:60s} "
                  f"-> {verdict['decision'].upper():5s} ({verdict['rule']})", flush=True)
            self._send(200, verdict)
        elif self.path == "/kill":
            if not isinstance(req.get("session_id"), str) or not req["session_id"]:
                self._send(400, {"error": "session_id required"})
                return
            BRAIN.kill(req["session_id"])
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):  # silence default access logging
        return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AgentAirlock decision service")
    ap.add_argument("--policy", default=None)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default=None,
                    help="persist to a SQLite DB (William-compatible) instead of in-memory graph")
    a = ap.parse_args(argv)
    global BRAIN
    if a.db:
        from provenance import Policy
        BRAIN = Brain(store=SqliteStore(a.db), policy=Policy.load(a.policy) if a.policy else None)
        print(f"AgentAirlock: persisting provenance to {a.db}", flush=True)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), _Handler)
    print(f"AgentAirlock decision service on http://127.0.0.1:{a.port} "
          f"(POST /decide, /kill; GET /health)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
