"""HTTP API for session sandboxes.

Callers (gateway, dashboard backend) must send `Authorization: Bearer $SANDBOX_API_KEY`.

  POST   /sessions                 create a sandbox -> includes session_token (only time it is returned)
  GET    /sessions                 list sandboxes
  GET    /sessions/{session_id}    one sandbox's status
  DELETE /sessions/{session_id}    destroy a sandbox
  POST   /sessions/resolve         {"token": ...} -> {"session_id": ...}  (gateway: who sent this request?)
  POST   /sessions/{session_id}/touch   mark activity (resolve does this too)
  POST   /reap                     run cleanup now
  GET    /healthz                  no auth

A background thread removes sandboxes that exited, are older than SANDBOX_MAX_AGE
(default 7200s), or idle past SANDBOX_IDLE_TIMEOUT (default 1800s), every
SANDBOX_REAP_INTERVAL seconds (default 60; 0 disables).

Run: SANDBOX_API_KEY=... uvicorn api:app --app-dir sandbox --port 9000
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from manager import SESSION_ID_RE, SandboxManager

log = logging.getLogger("sandbox.api")

API_KEY = os.getenv("SANDBOX_API_KEY")
if not API_KEY:
    API_KEY = secrets.token_urlsafe(24)
    log.warning("SANDBOX_API_KEY not set; generated one for this run: %s", API_KEY)

MAX_AGE = float(os.getenv("SANDBOX_MAX_AGE", "7200"))
IDLE_TIMEOUT = float(os.getenv("SANDBOX_IDLE_TIMEOUT", "1800"))
REAP_INTERVAL = float(os.getenv("SANDBOX_REAP_INTERVAL", "60"))

_bearer = HTTPBearer(auto_error=False)
_manager: SandboxManager | None = None


def _reaper_loop(stop: threading.Event) -> None:
    while not stop.wait(REAP_INTERVAL):
        try:
            get_manager().reap(max_age=MAX_AGE, idle_timeout=IDLE_TIMEOUT)
        except Exception:
            log.exception("reaper pass failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    stop = threading.Event()
    if REAP_INTERVAL > 0:
        threading.Thread(target=_reaper_loop, args=(stop,), daemon=True, name="reaper").start()
    yield
    stop.set()


app = FastAPI(title="a10 sandbox API", lifespan=lifespan)


def get_manager() -> SandboxManager:
    global _manager
    if _manager is None:
        _manager = SandboxManager()
    return _manager


def require_key(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> None:
    if creds is None or not secrets.compare_digest(creds.credentials, API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")


class CreateSession(BaseModel):
    session_id: str | None = Field(None, pattern=SESSION_ID_RE.pattern)
    env: dict[str, str] = Field(default_factory=dict)
    agents: int | None = Field(None, ge=1, description="size the sandbox for N parallel agents")


class ResolveToken(BaseModel):
    token: str


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/sessions", status_code=201, dependencies=[Depends(require_key)])
def create_session(body: CreateSession, mgr: SandboxManager = Depends(get_manager)):
    session_id = body.session_id or uuid.uuid4().hex
    if mgr.get(session_id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"session {session_id} already exists")
    try:
        return asdict(mgr.create(session_id, env=body.env, agents=body.agents))
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/sessions", dependencies=[Depends(require_key)])
def list_sessions(mgr: SandboxManager = Depends(get_manager)):
    return mgr.list()


@app.post("/sessions/resolve", dependencies=[Depends(require_key)])
def resolve(body: ResolveToken, mgr: SandboxManager = Depends(get_manager)):
    session_id = mgr.resolve_token(body.token)
    if session_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown token")
    return {"session_id": session_id}


@app.post("/reap", dependencies=[Depends(require_key)])
def reap(mgr: SandboxManager = Depends(get_manager)):
    return mgr.reap(max_age=MAX_AGE, idle_timeout=IDLE_TIMEOUT)


@app.post("/sessions/{session_id}/touch", status_code=204, dependencies=[Depends(require_key)])
def touch_session(session_id: str, mgr: SandboxManager = Depends(get_manager)):
    _get_or_404(mgr, session_id)
    mgr.touch(session_id)
    return Response(status_code=204)


@app.get("/sessions/{session_id}", dependencies=[Depends(require_key)])
def get_session(session_id: str, mgr: SandboxManager = Depends(get_manager)):
    info = _get_or_404(mgr, session_id)
    return info


@app.delete("/sessions/{session_id}", status_code=204, dependencies=[Depends(require_key)])
def delete_session(session_id: str, mgr: SandboxManager = Depends(get_manager)):
    _get_or_404(mgr, session_id)
    mgr.destroy(session_id)
    return Response(status_code=204)


def _get_or_404(mgr: SandboxManager, session_id: str) -> dict:
    if not SESSION_ID_RE.match(session_id):
        raise HTTPException(422, "invalid session id")
    info = mgr.get(session_id)
    if info is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"session {session_id} not found")
    return info
