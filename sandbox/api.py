"""HTTP API for session sandboxes.

Callers (gateway, dashboard backend) must send `Authorization: Bearer $SANDBOX_API_KEY`.

  POST   /sessions                 create a sandbox -> includes session_token (only time it is returned)
  GET    /sessions                 list sandboxes
  GET    /sessions/{session_id}    one sandbox's status
  DELETE /sessions/{session_id}    destroy a sandbox
  POST   /sessions/resolve         {"token": ...} -> {"session_id": ...}  (gateway: who sent this request?)
  GET    /healthz                  no auth

Run: SANDBOX_API_KEY=... uvicorn api:app --app-dir sandbox --port 9000
"""

from __future__ import annotations

import logging
import os
import secrets
import uuid
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

app = FastAPI(title="a10 sandbox API")
_bearer = HTTPBearer(auto_error=False)
_manager: SandboxManager | None = None


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
    return asdict(mgr.create(session_id, env=body.env))


@app.get("/sessions", dependencies=[Depends(require_key)])
def list_sessions(mgr: SandboxManager = Depends(get_manager)):
    return mgr.list()


@app.post("/sessions/resolve", dependencies=[Depends(require_key)])
def resolve(body: ResolveToken, mgr: SandboxManager = Depends(get_manager)):
    session_id = mgr.resolve_token(body.token)
    if session_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown token")
    return {"session_id": session_id}


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
