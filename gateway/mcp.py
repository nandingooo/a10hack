"""The gateway's tools as an MCP server (streamable HTTP, JSON responses), so agents such as
Claude Code can call them like built-in tools:

  claude mcp add --transport http gateway http://gateway:8080/mcp \
      --header "Authorization: Bearer $SESSION_TOKEN"

Each call goes through the same functions, tagging and rules as /tools/*.
"""

from __future__ import annotations

import json

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

import app as gw
from policy import SessionState

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {"name": "list_files", "description": "List files in the project workspace.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "read_file", "description": "Read a file from the project workspace.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "fetch_url", "description": "Fetch a web page (http/https). The only way to reach the web.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "send", "description": "Send data to a URL (HTTP POST).",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
                     "required": ["url"]}},
    {"name": "action", "description": "Perform a privileged action: delete, credentials, permissions, ...",
     "inputSchema": {"type": "object", "properties": {"kind": {"type": "string"}, "target": {"type": "string"}},
                     "required": ["kind"]}},
]

_HANDLERS = {
    "list_files": lambda args, s: gw.list_files(s),
    "read_file": lambda args, s: gw.read_file(gw.ReadFile(**args), s),
    "fetch_url": lambda args, s: gw.fetch_url(gw.Fetch(**args), s),
    "send": lambda args, s: gw.send(gw.Send(**args), s),
    "action": lambda args, s: gw.action(gw.Action(**args), s),
}


def _result(id_, result):
    return JSONResponse({"jsonrpc": "2.0", "id": id_, "result": result})


def _call_tool(name: str, args: dict, state: SessionState) -> dict:
    handler = _HANDLERS.get(name)
    if not handler:
        return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}
    try:
        out = handler(args or {}, state)
    except HTTPException as e:
        d = e.detail if isinstance(e.detail, dict) else {"reason": e.detail}
        text = (f"BLOCKED by the gateway ({d.get('rule', e.status_code)}): {d.get('reason')}"
                if e.status_code == 403 else f"error {e.status_code}: {d.get('reason')}")
        return {"content": [{"type": "text", "text": text}], "isError": True}
    except (TypeError, ValueError) as e:
        return {"content": [{"type": "text", "text": f"bad arguments: {e}"}], "isError": True}
    return {"content": [{"type": "text", "text": json.dumps(out)}], "isError": False}


@gw.app.post("/mcp")
async def mcp(request: Request, state: SessionState = Depends(gw.session)):
    try:
        msg = json.loads(await request.body())
    except ValueError:
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}}, status_code=400)
    if isinstance(msg, list):  # batches aren't needed by current clients
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "batches not supported"}}, status_code=400)
    method, id_ = msg.get("method"), msg.get("id")
    if id_ is None:  # notification (e.g. notifications/initialized)
        return Response(status_code=202)
    if method == "initialize":
        return _result(id_, {
            "protocolVersion": (msg.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "a10-gateway", "version": "0.1"},
        })
    if method == "ping":
        return _result(id_, {})
    if method == "tools/list":
        return _result(id_, {"tools": TOOLS})
    if method == "tools/call":
        p = msg.get("params") or {}
        from starlette.concurrency import run_in_threadpool  # tool handlers are blocking
        return _result(id_, await run_in_threadpool(_call_tool, p.get("name"), p.get("arguments"), state))
    return JSONResponse({"jsonrpc": "2.0", "id": id_,
                         "error": {"code": -32601, "message": f"method {method} not found"}})


@gw.app.get("/mcp")
def mcp_get():
    # No server-initiated stream; clients fall back to plain request/response.
    return Response(status_code=405)
