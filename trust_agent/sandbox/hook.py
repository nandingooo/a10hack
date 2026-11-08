"""AgentAirlock Claude Code hooks.

Claude Code fires this BEFORE each tool runs, passing the tool call as JSON on
stdin. We map it to an action, ask the decision service (which builds the graph
and runs trace_back), and enforce:
  exit 0  -> allow (tool runs)
  exit 2  -> block/stop (tool is cancelled; reason goes back to the agent)
Any error reaching the service -> exit 2 (fail closed).

Register this script for PreToolUse and for PostToolUse matching Read. The
second hook confirms text reads without sending their contents to the service.
Env: AIRLOCK_URL (default http://127.0.0.1:8787)
"""
import json
import os
import sys
import urllib.request

URL = os.environ.get("AIRLOCK_URL", "http://127.0.0.1:8787").rstrip("/")
READ = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

try:
    sys.stdout.reconfigure(encoding="utf-8")  # robust unicode on Windows pipes
except Exception:
    pass


def _emit(decision: str, rule: str, reason: str, confidence, action: str) -> int:
    """Structured PreToolUse response so Claude Code renders a clear, attributed
    block: a banner for the user + an explicit 'blocked by TrustAgent' reason
    fed back to the agent, so it's unmistakable this came from OUR service."""
    stopped = decision == "stop"
    label = "STOPPED  (session killed)" if stopped else ("BLOCKED" if decision != "ask" else "NEEDS APPROVAL")
    banner = (
        "\n"
        "==================  TRUSTAGENT GUARD  ==================\n"
        f"  {label}\n"
        f"  rule:    {rule}\n"
        f"  reason:  {reason} (confidence {confidence})\n"
        f"  action:  {action}\n"
        + ("  status:  SESSION KILLED - all further actions refused\n" if stopped else "")
        + "========================================================"
    )
    agent_reason = (
        f"BLOCKED BY THE TRUSTAGENT GUARD SERVICE (not the model's own safety). "
        f"rule={rule}; reason={reason}; confidence={confidence}; action={action}."
        + (" The session is now KILLED; every further tool call will also be refused." if stopped else "")
    )
    print(json.dumps({
        "systemMessage": banner,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask" if decision == "ask" else "deny",
            "permissionDecisionReason": agent_reason,
        },
    }))
    return 0


def to_request(ev: dict):
    tool = ev.get("tool_name") or ""
    inp = ev.get("tool_input") or {}
    session = ev.get("session_id") or "unknown"
    if tool in READ:
        return {"session_id": session, "op": "ReadFile",
                "target": inp.get("file_path") or inp.get("path") or inp.get("pattern") or "", "args": inp,
                "tool_use_id": ev.get("tool_use_id") if tool == "Read" else None}
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


def _post(path: str, payload: dict) -> dict:
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def _confirm_read(ev: dict) -> int:
    if ev.get("tool_name") != "Read":
        return 0
    response = ev.get("tool_response")
    if not isinstance(response, dict) or response.get("type") != "text":
        return 0
    file = response.get("file")
    content = file.get("content") if isinstance(file, dict) else None
    if not isinstance(content, str) or not content:
        return 0
    try:
        result = _post("/results", {
            "session_id": ev.get("session_id"),
            "tool_use_id": ev.get("tool_use_id"),
            "target": ev["tool_input"]["file_path"],
        })
        if not result.get("result_id"):
            raise ValueError("missing read result ID")
    except Exception:
        print(json.dumps({"continue": False, "stopReason": "TrustAgent could not record the read result."}))
    return 0


def handle_event(ev: dict) -> int:
    if ev.get("hook_event_name") == "PostToolUse":
        return _confirm_read(ev)
    if ev.get("hook_event_name") == "PostToolUseFailure":
        return 0
    req = to_request(ev)
    if req is None:
        return 0  # allow unmodeled tools (TodoWrite, Task, etc.)
    try:
        verdict = _post("/decide", req)
    except Exception as e:  # service down/unreachable -> fail closed
        action = f"{req['op']} {str(req.get('target', ''))[:120]}"
        return _emit("block", "fail_closed", f"decision service unreachable: {e}", 1.0, action)
    decision = verdict.get("decision", "allow")
    if decision in ("block", "stop", "ask"):
        action = f"{req['op']} {str(req.get('target', ''))[:120]}"
        return _emit(decision, verdict.get("rule", ""), verdict.get("reason", ""),
                     verdict.get("confidence"), action)
    return 0  # allow


def main() -> int:
    try:
        ev = json.load(sys.stdin)
    except Exception:
        ev = {}
    return handle_event(ev)


if __name__ == "__main__":
    sys.exit(main())
