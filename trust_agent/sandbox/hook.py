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
import hashlib
import json
import os
import sys
import urllib.request

URL = os.environ.get("AIRLOCK_URL", "http://127.0.0.1:8787") + "/decide"
READ = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
# Shell tools vary by platform: Claude Code uses "Bash" on macOS/Linux and
# "PowerShell" on Windows. All map to RunCommand so the command is decomposed
# and evaluated (not treated as an opaque unmodeled tool).
SHELL = {"Bash", "PowerShell", "Shell", "Cmd"}

try:
    sys.stdout.reconfigure(encoding="utf-8")  # robust unicode on Windows pipes
except Exception:
    pass


def _emit(decision: str, rule: str, reason: str, confidence, action: str) -> int:
    """Structured PreToolUse response so Claude Code renders a clear, attributed
    block: a banner for the user + an explicit 'blocked by TrustAgent' reason
    fed back to the agent, so it's unmistakable this came from OUR service."""
    stopped = decision == "stop"
    label = "STOPPED  (tool access revoked)" if stopped else ("BLOCKED" if decision != "ask" else "NEEDS APPROVAL")
    banner = (
        "\n"
        "==================  TRUSTAGENT GUARD  ==================\n"
        f"  {label}\n"
        f"  rule:    {rule}\n"
        f"  reason:  {reason} (confidence {confidence})\n"
        f"  action:  {action}\n"
        + ("  status:  SESSION REVOKED - modeled tool actions refused\n" if stopped else "")
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
    session = os.environ.get("AIRLOCK_SESSION") or ev.get("session_id")
    if tool in READ:
        return {"session_id": session, "op": "ReadFile",
                "target": inp.get("file_path") or inp.get("path") or inp.get("pattern") or "", "args": inp}
    if tool in WRITE:
        return {"session_id": session, "op": "WriteFile",
                "target": inp.get("file_path") or inp.get("path") or "", "args": inp}
    if tool in SHELL:
        return {"session_id": session, "op": "RunCommand",
                "target": inp.get("command") or inp.get("script") or "", "args": inp}
    if tool == "WebFetch":
        url = str(inp.get("url") or "")
        return {"session_id": session, "op": "NetworkRequest", "target": url, "args": {"url": url, "method":"GET"}}
    if tool.startswith("mcp__"):
        return {"session_id": session, "op": "CallTool", "target": tool, "args": inp}
    return {"session_id": session, "op": "CallTool", "target": tool, "args": inp}


def main() -> int:
    try:
        ev = json.load(sys.stdin)
    except Exception:
        ev = {}
    if not isinstance(ev, dict) or not isinstance(ev.get("tool_input", {}), dict):
        return _emit("block", "invalid_event", "Malformed tool event", 1.0, "unknown")
    if ev.get("hook_event_name") in ("PostToolUse", "PostToolUseFailure", "PermissionDenied"):
        response = ev.get("tool_response") or {}
        success = ev["hook_event_name"] == "PostToolUse"
        if isinstance(response, dict):
            success = success and not response.get("is_error", False) and response.get("exit_code", 0) == 0
        data = json.dumps({"session_id": os.environ.get("AIRLOCK_SESSION") or ev.get("session_id"), "tool_use_id": ev.get("tool_use_id"), "success": success,
            "exposure": "none" if ev["hook_event_name"] == "PermissionDenied" else "exposed" if response or ev.get("error") else "unknown",
            "output_digest": hashlib.sha256(json.dumps(response or ev.get("error", ""), sort_keys=True).encode()).hexdigest()}).encode()
        try:
            result = urllib.request.urlopen(urllib.request.Request(URL.replace('/decide', '/complete'), data=data,
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ.get("AIRLOCK_SENSOR_TOKEN", "")}), timeout=5)
            if not json.loads(result.read()).get("ok"):
                raise ValueError("completion rejected")
        except Exception as exc:
            print(f"TrustAgent: context completion failed: {exc}", file=sys.stderr)
            return 2
        return 0
    req = to_request(ev)
    req.update(phase="before", tool_use_id=ev.get("tool_use_id"), cwd=ev.get("cwd", os.getcwd()))
    try:
        data = json.dumps(req).encode()
        r = urllib.request.urlopen(
            urllib.request.Request(URL, data=data, headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ.get("AIRLOCK_SENSOR_TOKEN", "")}),
            timeout=5,
        )
        verdict = json.loads(r.read())
        if not isinstance(verdict, dict) or verdict.get("decision") not in ("allow", "block", "stop", "ask"):
            raise ValueError("Invalid guard verdict")
    except Exception as e:  # service down/unreachable -> fail closed
        action = f"{req['op']} {str(req.get('target', ''))[:120]}"
        return _emit("block", "fail_closed", f"decision service unreachable: {e}", 1.0, action)
    decision = verdict.get("decision", "block")
    if decision not in ("allow", "block", "stop", "ask"):
        return _emit("block", "invalid_verdict", "Invalid guard response", 1.0, req["op"])
    if decision in ("block", "stop", "ask"):
        if decision in ('block','stop'):
            try:
                acknowledgment=json.dumps({'session_id':req['session_id'],'tool_use_id':req['tool_use_id']}).encode()
                urllib.request.urlopen(urllib.request.Request(URL.replace('/decide','/enforcement'),data=acknowledgment,
                    headers={'Content-Type':'application/json','Authorization':'Bearer '+os.environ.get('AIRLOCK_SENSOR_TOKEN','')}),timeout=2).close()
            except Exception:
                pass # a missing audit acknowledgment never turns denial into allowance
        action = f"{req['op']} {str(req.get('target', ''))[:120]}"
        evidence = "; ".join(str(e.get("target") or e["id"]) for e in verdict.get("evidence", []))
        return _emit(decision, verdict.get("rule", ""), verdict.get("reason", "") + ("; evidence: " + evidence if evidence else ""),
                     verdict.get("confidence"), action)
    return 0  # allow


if __name__ == "__main__":
    sys.exit(main())
