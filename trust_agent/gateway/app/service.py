"""AgentAirlock decision service (the persistent gateway "brain").

Keeps session provenance across hook calls. PreToolUse submits a planned action
and enforces the verdict. PostToolUse confirms reads that returned data.

Endpoints (stdlib http.server, no deps):
  POST /decide  {session_id, op, target, origin?, args}  -> {decision, rule, reason, confidence}
  POST /results {session_id, tool_use_id, target}         -> {result_id}
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
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from uuid import uuid4

_APP = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _APP not in sys.path:
    sys.path.insert(0, _APP)

from provenance import (  # noqa: E402
    ActionProps, Channel, ContextEntry, GraphStore, Kind, Labeler, Op,
    Sensitivity, SqliteStore, Trust,
)
import provenance.command as cmdparse  # noqa: E402
from monitor.daemon import default_policy, resolve_origin  # noqa: E402

ACTION_OPS = {"WriteFile", "DeleteFile", "RunCommand", "NetworkRequest", "CallTool"}
_OP = {
    "ReadFile": Op.READ_FILE, "WriteFile": Op.WRITE_FILE, "DeleteFile": Op.DELETE_FILE,
    "RunCommand": Op.RUN_COMMAND, "NetworkRequest": Op.NETWORK_REQUEST, "CallTool": Op.CALL_TOOL,
}
_DESTRUCTIVE = ("rm -rf", "rm -r ", "git push --force", "git push -f", "drop table", "mkfs", "sudo ")


def _read_id(session, tool_use_id):
    if (isinstance(session, str) and session and isinstance(tool_use_id, str)
            and tool_use_id and ":" not in tool_use_id):
        return f"{session}:read:{tool_use_id}"
    return None


class Brain:
    """The decision engine: label -> append to graph -> trace_back -> decide."""

    def __init__(self, store=None) -> None:
        self.store = store if store is not None else GraphStore()
        self.labeler = Labeler(default_policy())
        self.killed: set[str] = set()

    def _next_id(self, session: str) -> str:
        return f"{session}:e-{uuid4().hex}"

    def _is_killed(self, session: str) -> bool:
        if session in self.killed:
            return True
        checker = getattr(self.store, "is_killed", None)
        return bool(checker(session)) if checker else False

    def kill(self, session: str) -> None:
        self.killed.add(session)
        store_kill = getattr(self.store, "kill", None)   # persist the kill (SqliteStore)
        if store_kill:
            store_kill(session)

    def _append(self, session, op, target, labels, kind, action_props, origin):
        e = ContextEntry(id=self._next_id(session), ts=time.time(), session_id=session, kind=kind,
                         channel=Channel.HOOK, op=op, target=target, origin=origin,
                         labels=labels, action_props=action_props)
        self.store.append(e)
        return e

    def record_read_result(self, req: dict) -> str:
        session = req.get("session_id")
        read_id = _read_id(session, req.get("tool_use_id"))
        if read_id is None or self._is_killed(session):
            raise ValueError("Read result requires an active session and a tool call ID.")
        read = self.store.get_entry(session, read_id)
        if read is None or read.verdict != "allow" or read.target != req.get("target"):
            raise ValueError("Read result does not match an allowed read in this session.")
        result_id = f"{read_id}:result"
        if self.store.get_entry(session, result_id) is None:
            self.store.append(replace(read, id=result_id, ts=time.time(), kind=Kind.READ_RESULT, verdict=None))
        return result_id

    def _decide_bash(self, session, cmd):
        """Evaluate the file reads and outbound connections a shell command
        performs. Returns a verdict dict if the command is dangerous, else None."""
        # 1. record untrusted/secret file reads the command references (provenance)
        for raw in cmdparse.file_tokens(cmd):
            ftok = raw if raw.startswith("/") else "/" + raw  # relative -> absolute for glob/marker match
            origin = resolve_origin("ReadFile", ftok)
            lbl = self.labeler.label(ftok, origin)
            if lbl.bait or self.labeler.is_bait_target("RunCommand", ftok, cmd):
                self.kill(session)
                return _v("stop", "bait_touched", "bait file referenced in shell command", 1.0)
            if lbl.sensitivity == Sensitivity.SECRET or lbl.effective_trust == Trust.UNTRUSTED:
                kind = Kind.SECRET if lbl.sensitivity == Sensitivity.SECRET else Kind.SOURCE
                self._append(session, Op.READ_FILE, ftok, lbl, kind, None, origin)
        # 2. outbound connections inside the command (curl/wget/...)
        for host in cmdparse.hosts_in(cmd):
            if not self.labeler.approved_host(host):
                ne = self._append(session, Op.NETWORK_REQUEST, host,
                                  self.labeler.label(host, "web"), Kind.ACTION,
                                  ActionProps(is_exit=True), "web")
                agg = self.store.aggregate(session, ne)
                if agg.reached_secret:
                    return _v("block", "secret_exit",
                              "secret data reaching an unapproved exit (shell)", agg.confidence)
                if agg.reached_untrusted:
                    return _v("block", "lethal_trifecta",
                              "untrusted input reaching an unapproved exit (shell)", agg.confidence)
                return _v("block", "egress_allowlist",
                          "shell command exits to an unapproved host", 1.0)
        return None

    def decide(self, req: dict) -> dict:
        session = req.get("session_id") or "unknown"
        op = req.get("op") or "ReadFile"
        target = req.get("target") or ""
        args = req.get("args") or {}

        if self._is_killed(session):
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

        read_id = _read_id(session, req.get("tool_use_id")) if op == "ReadFile" and not bait else None
        if read_id is not None:
            previous = self.store.get_entry(session, read_id)
            if previous is not None:
                if previous.target != target or previous.origin != origin:
                    return _v("block", "read_id_conflict", "tool call ID already belongs to another read", 1.0)
                return _v("allow", "read_recorded", "context read; labeled and recorded", 1.0)

        action_props = None
        if is_action:
            is_exit = op == "NetworkRequest" and not self.labeler.approved_host(target)
            destructive = op == "RunCommand" and any(p in blob.lower() for p in _DESTRUCTIVE)
            action_props = ActionProps(is_exit=is_exit, is_destructive=destructive)

        entry = ContextEntry(
            id=read_id or self._next_id(session), ts=time.time(), session_id=session, kind=kind,
            channel=Channel.HOOK, op=_OP[op], target=target, origin=origin,
            labels=labels, action_props=action_props,
            verdict="allow" if read_id is not None else None,
        )
        self.store.append(entry)

        # bait is checked on every event: touching it = confirmed compromise
        if bait:
            self.kill(session)
            return _v("stop", "bait_touched", "bait/canary accessed -> hijack confirmed", 1.0)

        if not is_action:
            return _v("allow", "read_recorded", "context read; labeled and recorded", 1.0)

        if op == "CallTool" and (target == "post_support_update" or (
            target.startswith("mcp__") and target.endswith("__post_support_update")
        )):
            for result in reversed(self.store.get_entries(session)):
                if result.kind == Kind.READ_RESULT and result.labels.sensitivity == Sensitivity.SECRET:
                    verdict = _v("block", "secret_external_write", "a confirmed secret read preceded the support update", 1.0)
                    verdict["evidence_ids"] = [result.id]
                    return verdict

        # Decompose a Bash command into the actions it performs (reads + exits),
        # so a single `cat .env && curl evil` is not opaque to the guard.
        if op == "RunCommand":
            sub = self._decide_bash(session, str(args.get("command") or target or ""))
            if sub is not None:
                return sub

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
_BRAIN_LOCK = Lock()


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
        except (UnicodeDecodeError, json.JSONDecodeError):
            req = None
        if not isinstance(req, dict):
            self._send(400, {"error": "expected a JSON object"})
            return
        if self.path == "/decide":
            with _BRAIN_LOCK:
                verdict = BRAIN.decide(req)
            print(f"[decide] {str(req.get('op')):14s} {str(req.get('target'))[:60]:60s} "
                  f"-> {verdict['decision'].upper():5s} ({verdict['rule']})", flush=True)
            self._send(200, verdict)
        elif self.path == "/results":
            try:
                with _BRAIN_LOCK:
                    result_id = BRAIN.record_read_result(req)
            except ValueError as error:
                self._send(400, {"error": str(error)})
            else:
                self._send(200, {"result_id": result_id})
        elif self.path == "/kill":
            with _BRAIN_LOCK:
                BRAIN.kill(req.get("session_id") or "")
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):  # silence default access logging
        return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AgentAirlock decision service")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default=None,
                    help="persist to a SQLite DB instead of the in-memory graph")
    a = ap.parse_args(argv)
    global BRAIN
    if a.db:
        BRAIN = Brain(store=SqliteStore(a.db))
        print(f"AgentAirlock: persisting provenance to {a.db}", flush=True)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), _Handler)
    print(f"AgentAirlock decision service on http://127.0.0.1:{a.port} "
          f"(POST /decide, /results, /kill; GET /health)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
