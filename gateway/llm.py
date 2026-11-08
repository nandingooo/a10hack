"""Model API proxy: the agent's reasoning calls leave the sandbox only through here.

Inside the sandbox:  ANTHROPIC_BASE_URL=http://gateway:8080/llm
                     ANTHROPIC_AUTH_TOKEN=$SESSION_TOKEN   (sent as "Authorization: Bearer ...")
The gateway swaps the session token for the real API key, which never enters a sandbox,
forwards to the pinned upstream, and streams the reply back byte for byte as it arrives.

Before forwarding it:
  * allows only the model endpoints (POST /v1/messages, /v1/messages/count_tokens);
  * removes tools that run on the provider's servers (web search, web fetch, code
    execution) and remote MCP servers, since those would reach the outside world
    without passing the gateway;
  * refuses requests with URL-sourced content (images/documents the provider would download
    from an agent-chosen URL, an exfiltration path around R2/R3);
  * applies decide_llm (a decoy read blocks model calls too) and logs metadata only.
"""

from __future__ import annotations

import json
import os
import time

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

import app as gw
from policy import SessionState, decide_llm

UPSTREAM = os.getenv("LLM_UPSTREAM", "https://api.anthropic.com").rstrip("/")
API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ALLOWED_PATHS = {"v1/messages", "v1/messages/count_tokens"}
SERVER_TOOL_PREFIXES = ("web_search", "web_fetch", "code_execution")
DROP_FIELDS = ("mcp_servers", "container")
FORWARD_REQ_HEADERS = ("anthropic-version", "anthropic-beta", "content-type", "accept")
FORWARD_RESP_HEADERS = ("content-type", "request-id", "anthropic-organization-id")

# One pooled client: keeps connections to the provider open across calls (no TLS
# handshake per call) and doesn't cap concurrency at a thread pool's size.
_client = httpx.AsyncClient(
    timeout=httpx.Timeout(connect=10, read=600, write=60, pool=30),
    limits=httpx.Limits(max_connections=1000, max_keepalive_connections=100),
)


def sanitize(body: dict) -> tuple[dict, list[str]]:
    """Remove server-side tools and remote MCP servers. Returns (body, what was removed)."""
    removed = []
    tools = body.get("tools")
    if isinstance(tools, list):
        kept = []
        for t in tools:
            ttype = str(t.get("type", "")) if isinstance(t, dict) else ""
            if ttype.startswith(SERVER_TOOL_PREFIXES):
                removed.append(f"tool:{ttype}")
            else:
                kept.append(t)
        body["tools"] = kept
        if not kept:
            body.pop("tools")
            body.pop("tool_choice", None)
    for f in DROP_FIELDS:
        if f in body:
            body.pop(f)
            removed.append(f)
    return body, removed


def url_sources(node) -> int:
    """Count content blocks the provider would download itself ("source": {"type": "url", ...}
    on image/document blocks, at any depth, e.g. inside tool results). The URL is chosen by
    the agent, so it is an outbound request that never passes R2/R3: an agent could put
    secrets in the query string."""
    if isinstance(node, dict):
        src = node.get("source")
        own = 1 if isinstance(src, dict) and src.get("type") == "url" else 0
        return own + sum(url_sources(v) for v in node.values())
    if isinstance(node, list):
        return sum(url_sources(v) for v in node)
    return 0


async def session_async(request: Request) -> SessionState:
    """Like gw.session, but cached tokens skip the thread-pool hop (hot path on every call)."""
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip()
    session_id = gw._token_cache.get(token)
    if session_id:
        return gw.get_session(session_id)
    return await run_in_threadpool(gw.session, header)


@gw.app.api_route("/llm/{path:path}", methods=["GET", "POST"])
async def llm_proxy(path: str, request: Request):
    state = await session_async(request)
    path = path.strip("/")
    if request.method != "POST" or path not in ALLOWED_PATHS:
        gw.record(state, "llm_call", {"path": path, "method": request.method},
                  gw.Decision("block", "llm-path", "only the model endpoints are allowed"))
        raise HTTPException(403, {"decision": "block", "rule": "llm-path", "reason": f"/{path} not allowed"})
    if not API_KEY:
        raise HTTPException(503, "gateway has no model API key configured")

    try:
        body = json.loads(await request.body())
        assert isinstance(body, dict)
    except (ValueError, AssertionError):
        raise HTTPException(400, "body must be a JSON object")
    body, removed = sanitize(body)

    meta = {"path": path, "model": body.get("model"), "stream": bool(body.get("stream")),
            "messages": len(body.get("messages") or []), "removed": removed}
    d = decide_llm(state)
    if d.decision == "allow" and (n := url_sources(body)):
        # The URL itself is not logged: it may carry the data being smuggled out.
        meta["url_sources"] = n
        d = gw.Decision("block", "llm-url-source",
                        "content with a URL source would make the provider fetch an agent-chosen URL; "
                        "fetch it with fetch_url and send the content inline", alert=True)
    if d.decision != "allow":
        gw.record(state, "llm_call", meta, d)
        gw.enforce(d)

    headers = {h: request.headers[h] for h in FORWARD_REQ_HEADERS if h in request.headers}
    headers["x-api-key"] = API_KEY
    headers["accept-encoding"] = "identity"
    started = time.perf_counter()
    upstream_req = _client.build_request("POST", f"{UPSTREAM}/{path}", content=json.dumps(body), headers=headers)
    try:
        upstream = await _client.send(upstream_req, stream=True)
    except httpx.HTTPError as e:
        gw.record(state, "llm_call", {**meta, "error": type(e).__name__}, d)
        raise HTTPException(502, "model provider unreachable")
    resp_headers = {h: upstream.headers[h] for h in FORWARD_RESP_HEADERS if h in upstream.headers}

    async def relay():
        first = None
        size = 0
        try:
            async for chunk in upstream.aiter_raw():
                if first is None:
                    first = time.perf_counter()
                size += len(chunk)
                yield chunk
        finally:
            await upstream.aclose()
            end = time.perf_counter()
            gw.record(state, "llm_call", {
                **meta, "status": upstream.status_code, "bytes": size,
                "upstream_first_byte_ms": round(((first or end) - started) * 1000, 1),
                "duration_ms": round((end - started) * 1000, 1)}, d)

    if body.get("stream"):
        return StreamingResponse(relay(), status_code=upstream.status_code, headers=resp_headers)
    content = b"".join([c async for c in relay()])
    return Response(content, status_code=upstream.status_code, headers=resp_headers)
