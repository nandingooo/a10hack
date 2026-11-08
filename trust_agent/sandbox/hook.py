"""AgentAirlock PreToolUse hook (thin, fail-closed client).

Claude Code fires this BEFORE each tool runs, passing the tool call as JSON on
stdin. We map it to an action, ask the decision service (which builds the graph
and runs trace_back), and enforce:
  exit 0  -> allow (tool runs)
  exit 2  -> block/stop (tool is cancelled; reason goes back to the agent)
Any error reaching the service -> exit 2 (fail closed).

Install via a project .claude/settings.json:
  {"hooks":{"PreToolUse":[{"matcher":"*","hooks":[
     {"type":"command","command":"python \"<abs>/sandbox/hook.py\""}]}]}}
Env: AIRLOCK_URL (default http://127.0.0.1:8787)
"""
import json
import os
import sys
import urllib.request

URL = os.environ.get("AIRLOCK_URL", "http://127.0.0.1:8787") + "/decide"
READ = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

try:
    sys.stdout.reconfigure(encoding="utf-8")  # robust unicode on Windows pipes
except Exception:
    pass


def _respond(permission: str, label: str, rule: str, reason: str) -> int:
    """Structured PreToolUse response so Claude Code renders a clean denial
    (shown in red to the user, reason fed back to the agent)."""
    msg = f"TrustAgent {label} [{rule}]: {reason}"
    print(json.dumps({
        "systemMessage": msg,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,          # "deny" | "ask" | "allow"
            "permissionDecisionReason": msg,
        },
    }))
    return 0


def _deny(rule: str, reason: str) -> int:
    return _respond("deny", "BLOCKED", rule, reason)


def _ask(rule: str, reason: str) -> int:
    return _respond("ask", "NEEDS APPROVAL", rule, reason)


def to_request(ev: dict):
    tool = ev.get("tool_name") or ""
    inp = ev.get("tool_input") or {}
    session = ev.get("session_id") or "unknown"
    if tool in READ:
        return {"session_id": session, "op": "ReadFile",
                "target": inp.get("file_path") or inp.get("path") or inp.get("pattern") or "", "args": inp}
    if tool in WRITE:
        return {"session_id": session, "op": "WriteFile",
                "target": inp.get("file_path") or inp.get("path") or "", "args": inp}
    if tool == "Bash":
        return {"session_id": session, "op": "RunCommand", "target": inp.get("command") or "", "args": inp}
    if tool == "WebFetch":
        url = str(inp.get("url") or "")
        host = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
        return {"session_id": session, "op": "NetworkRequest", "target": host, "args": {"url": url}}
    if tool.startswith("mcp__"):
        return {"session_id": session, "op": "CallTool", "target": tool, "args": inp}
    return None  # a tool we don't model -> allow


def main() -> int:
    try:
        ev = json.load(sys.stdin)
    except Exception:
        ev = {}
    req = to_request(ev)
    if req is None:
        return 0  # allow unmodeled tools (TodoWrite, Task, etc.)
    try:
        data = json.dumps(req).encode()
        r = urllib.request.urlopen(
            urllib.request.Request(URL, data=data, headers={"Content-Type": "application/json"}),
            timeout=5,
        )
        verdict = json.loads(r.read())
    except Exception as e:  # service down/unreachable -> fail closed
        return _deny("fail_closed", f"decision service unreachable: {e}")
    decision = verdict.get("decision", "allow")
    rule = verdict.get("rule", "")
    reason = f"{verdict.get('reason', '')} (confidence {verdict.get('confidence')})"
    if decision in ("block", "stop"):
        return _deny(rule, reason)
    if decision == "ask":
        return _ask(rule, reason)
    return 0  # allow


if __name__ == "__main__":
    sys.exit(main())
