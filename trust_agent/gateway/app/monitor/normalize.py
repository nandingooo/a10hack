"""Parse a Claude Code transcript JSONL line into Activities (stdlib only).

Claude Code writes one JSON object per line to
``~/.claude/projects/<slug(cwd)>/<sessionId>.jsonl``. Assistant messages carry
``message.content`` with ``tool_use`` blocks ({name, input}). We extract each
tool call as an Activity the labeler can classify. Defensive about schema drift.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime

TOOL_READ = {"Read", "Grep", "Glob", "NotebookRead"}
TOOL_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


@dataclass
class Activity:
    session_id: str
    ts: float
    op: str          # ReadFile | WriteFile | RunCommand | NetworkRequest | CallTool
    target: str      # path, host, or tool name
    kind: str        # "source" | "action"
    tool_name: str
    raw_input: dict


def _parse_ts(v: object) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return time.time()
    return time.time()


def _host_from_url(url: str) -> str:
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0].split("?", 1)[0]


def _from_tool_use(block: dict, session_id: str, ts: float) -> list[Activity]:
    name = block.get("name") or ""
    inp = block.get("input") if isinstance(block.get("input"), dict) else {}

    def act(op: str, target: str, kind: str) -> list[Activity]:
        return [Activity(session_id, ts, op, str(target), kind, name, inp)] if target else []

    if name in TOOL_READ:
        return act("ReadFile", inp.get("file_path") or inp.get("path") or inp.get("pattern") or "", "source")
    if name in TOOL_WRITE:
        return act("WriteFile", inp.get("file_path") or inp.get("path") or "", "action")
    if name == "Bash":
        return act("RunCommand", inp.get("command") or "", "action")
    if name == "WebFetch":
        return act("NetworkRequest", _host_from_url(str(inp.get("url") or "")), "action")
    if name.startswith("mcp__"):
        return [Activity(session_id, ts, "CallTool", name, "action", name, inp)]
    return []


def normalize_line(line: str, default_session: str = "") -> list[Activity]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return []
    if not isinstance(obj, dict):
        return []
    session_id = obj.get("sessionId") or default_session
    ts = _parse_ts(obj.get("timestamp"))
    msg = obj.get("message")
    if not isinstance(msg, dict):
        return []
    content = msg.get("content")
    if not isinstance(content, list):
        return []
    acts: list[Activity] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            acts.extend(_from_tool_use(block, session_id, ts))
    return acts
