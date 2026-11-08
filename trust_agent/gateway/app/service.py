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
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_APP = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _APP not in sys.path:
    sys.path.insert(0, _APP)

from provenance import (  # noqa: E402
    ActionProps, Channel, ContextEntry, GraphStore, Kind, Labeler, Op,
    Sensitivity, new_entry_id,
)
from monitor.daemon import default_policy, resolve_origin  # noqa: E402

ACTION_OPS = {"WriteFile", "DeleteFile", "RunCommand", "NetworkRequest", "CallTool"}
_OP = {
    "ReadFile": Op.READ_FILE, "WriteFile": Op.WRITE_FILE, "DeleteFile": Op.DELETE_FILE,
    "RunCommand": Op.RUN_COMMAND, "NetworkRequest": Op.NETWORK_REQUEST, "CallTool": Op.CALL_TOOL,
}
_DESTRUCTIVE = ("rm -rf", "rm -r ", "git push --force", "git push -f", "drop table", "mkfs", "sudo ")


class Brain:
    """The decision engine: label -> append to graph -> trace_back -> decide."""

    def __init__(self) -> None:
        self.store = GraphStore()
        self.labeler = Labeler(default_policy())
        self.killed: set[str] = set()
        self._seq: dict[str, int] = {}

    def _next_id(self, session: str) -> str:
        self._seq[session] = self._seq.get(session, 0) + 1
        return new_entry_id(session, self._seq[session])

    def kill(self, session: str) -> None:
        self.killed.add(session)

    def decide(self, req: dict) -> dict:
        session = req.get("session_id") or "unknown"
        op = req.get("op") or "ReadFile"
        target = req.get("target") or ""
        args = req.get("args") or {}

        if session in self.killed:
            return _v("stop", "session_killed", "session already terminated", 1.0)

        origin = req.get("origin") or resolve_origin(op, target)
        labels = self.labeler.label(target, origin)
        is_action = op in ACTION_OPS
        if not is_action and labels.sensitivity == Sensitivity.SECRET:
            kind = Kind.SECRET
        elif is_action:
            kind = Kind.ACTION
        else:
            kind = Kind.SOURCE

        blob = " ".join(str(x) for x in args.values())
        bait = labels.bait or self.labeler.is_bait_target(op, target, blob)

        action_props = None
        if is_action:
            is_exit = op == "NetworkRequest" and not self.labeler.approved_host(target)
            destructive = op == "RunCommand" and any(p in blob.lower() for p in _DESTRUCTIVE)
            action_props = ActionProps(is_exit=is_exit, is_destructive=destructive)

        entry = ContextEntry(
            id=self._next_id(session), ts=time.time(), session_id=session, kind=kind,
            channel=Channel.HOOK, op=_OP[op], target=target, origin=origin,
            labels=labels, action_props=action_props,
        )
        self.store.append(entry)

        # bait is checked on every event: touching it = confirmed compromise
        if bait:
            self.kill(session)
            return _v("stop", "bait_touched", "bait/canary accessed -> hijack confirmed", 1.0)

        if not is_action:
            return _v("allow", "read_recorded", "context read; labeled and recorded", 1.0)

        agg = self.store.aggregate(session, entry)   # trace_back over the graph
        c = agg.confidence
        if agg.reached_secret and action_props.is_exit:
            return _v("block", "secret_exit", "secret data reaching an unapproved exit", c)
        if agg.reached_untrusted and action_props.is_exit:
            return _v("block" if c >= 0.4 else "ask", "lethal_trifecta",
                      "untrusted input reaching an unapproved exit", c)
        if agg.reached_untrusted and action_props.is_destructive:
            return _v("block" if c >= 0.4 else "ask", "untrusted_destructive",
                      "untrusted input driving a destructive action", c)
        if action_props.is_exit:
            return _v("block", "egress_allowlist", "exit to an unapproved host", 1.0)
        return _v("allow", "no_dangerous_flow", "no dangerous provenance detected", 1.0)


def _v(decision: str, rule: str, reason: str, confidence: float) -> dict:
    return {"decision": decision, "rule": rule, "reason": reason, "confidence": round(confidence, 2)}


BRAIN = Brain()


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            req = {}
        if self.path == "/decide":
            verdict = BRAIN.decide(req)
            print(f"[decide] {str(req.get('op')):14s} {str(req.get('target'))[:60]:60s} "
                  f"-> {verdict['decision'].upper():5s} ({verdict['rule']})", flush=True)
            self._send(200, verdict)
        elif self.path == "/kill":
            BRAIN.kill(req.get("session_id") or "")
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):  # silence default access logging
        return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AgentAirlock decision service")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args(argv)
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
