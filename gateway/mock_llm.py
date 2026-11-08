"""Stand-in for the Anthropic Messages API, for tests and latency benchmarks without a key.

Streams real-format SSE events with a configurable time-to-first-token and per-token delay.
Rejects requests without the expected x-api-key (proves the gateway injects it).
GET /_last returns the last request body it received (proves sanitizing).

Scripted tool use: if the conversation's first user message has lines like
  CALL read_file {"path": "docs/readme.md"}
the mock answers with those tool calls one per turn (as mcp__gateway__<tool>, only if the
request offers that tool), then a final text reply quoting each tool result it received.

Run: MOCK_KEY=mock-key uvicorn mock_llm:app --app-dir gateway --port 8090
"""

import asyncio
import json
import os
import re

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

MOCK_KEY = os.getenv("MOCK_KEY", "mock-key")
TTFT_MS = float(os.getenv("MOCK_TTFT_MS", "500"))
TOKENS = int(os.getenv("MOCK_TOKENS", "50"))
TOKEN_MS = float(os.getenv("MOCK_TOKEN_MS", "20"))
REPLY = os.getenv("MOCK_REPLY", "Hello from the mock model.")

app = FastAPI()
last: dict = {}


def sse(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


@app.get("/_last")
def get_last():
    return last


@app.post("/v1/messages/count_tokens")
async def count_tokens(request: Request, x_api_key: str = Header("")):
    if x_api_key != MOCK_KEY:
        raise HTTPException(401, "bad api key")
    return {"input_tokens": len(await request.body()) // 4}


CALL_RE = re.compile(r"^CALL (\w+) (\{.*\})\s*$", re.M)


def _texts(content):
    if isinstance(content, str):
        return [content]
    return [b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text"]


def _tool_results(messages):
    out = []
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    c = b.get("content")
                    out.append(" ".join(_texts(c)) if not isinstance(c, str) else c)
    return out


def plan(body):
    """Next scripted step: ("tool", name, input) or ("text", reply)."""
    messages = body.get("messages") or []
    first_user = next((m for m in messages if m.get("role") == "user"), {})
    calls = CALL_RE.findall("\n".join(_texts(first_user.get("content"))))
    offered = {t.get("name") for t in body.get("tools") or []}
    done = _tool_results(messages)
    if calls and len(done) < len(calls):
        name, args = calls[len(done)]
        full = f"mcp__gateway__{name}"
        if full in offered:
            return ("tool", full, json.loads(args))
    if done:
        return ("text", " | ".join(f"result {i + 1}: {r[:160]}" for i, r in enumerate(done)))
    return ("text", None)


@app.post("/v1/messages")
async def messages(request: Request, x_api_key: str = Header("")):
    if x_api_key != MOCK_KEY:
        return JSONResponse({"type": "error", "error": {"type": "authentication_error",
                                                        "message": "invalid x-api-key"}}, status_code=401)
    body = await request.json()
    last.clear()
    last.update(body)
    model = body.get("model", "mock")
    step = plan(body)
    reply = step[1] if step[0] == "text" and step[1] else REPLY
    words = (reply + " ") * (1 if step[1] else max(1, TOKENS // max(1, len(reply.split()))))
    pieces = [w + " " for w in words.split()][:max(TOKENS, len(reply.split()))]
    msg = {"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": [],
           "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 0}}

    if step[0] == "tool":
        tool_block = {"type": "tool_use", "id": f"toolu_mock_{len(_tool_results(body['messages']))}",
                      "name": step[1], "input": step[2]}
        if not body.get("stream"):
            await asyncio.sleep(TTFT_MS / 1000)
            return {**msg, "content": [tool_block], "stop_reason": "tool_use"}

        async def tool_stream():
            await asyncio.sleep(TTFT_MS / 1000)
            yield sse("message_start", {"type": "message_start", "message": msg})
            yield sse("content_block_start", {"type": "content_block_start", "index": 0,
                                              "content_block": {**tool_block, "input": {}}})
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {
                "type": "input_json_delta", "partial_json": json.dumps(step[2])}})
            yield sse("content_block_stop", {"type": "content_block_stop", "index": 0})
            yield sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use",
                                        "stop_sequence": None}, "usage": {"output_tokens": 20}})
            yield sse("message_stop", {"type": "message_stop"})

        return StreamingResponse(tool_stream(), media_type="text/event-stream")

    if not body.get("stream"):
        await asyncio.sleep((TTFT_MS + TOKEN_MS * len(pieces)) / 1000)
        return {**msg, "content": [{"type": "text", "text": "".join(pieces).strip()}],
                "stop_reason": "end_turn", "usage": {"input_tokens": 10, "output_tokens": len(pieces)}}

    async def stream():
        await asyncio.sleep(TTFT_MS / 1000)
        yield sse("message_start", {"type": "message_start", "message": msg})
        yield sse("content_block_start", {"type": "content_block_start", "index": 0,
                                          "content_block": {"type": "text", "text": ""}})
        for p in pieces:
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                              "delta": {"type": "text_delta", "text": p}})
            await asyncio.sleep(TOKEN_MS / 1000)
        yield sse("content_block_stop", {"type": "content_block_stop", "index": 0})
        yield sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn",
                                    "stop_sequence": None}, "usage": {"output_tokens": len(pieces)}})
        yield sse("message_stop", {"type": "message_stop"})

    return StreamingResponse(stream(), media_type="text/event-stream")
