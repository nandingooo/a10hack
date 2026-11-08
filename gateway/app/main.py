import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
from contextlib import closing
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .policy import SESSION_KILLED, DecideRequest, ToolResult, decide, file_labels
from .store import Store

log = logging.getLogger("airlock.guard")


class CreateSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def bearer_hash(authorization: Annotated[str, Header()] = "") -> str:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "A bearer token is required.")
    return token_hash(token)


def create_app() -> FastAPI:
    operator_token = os.environ.get("AIRLOCK_OPERATOR_TOKEN", "")
    if len(operator_token) < 32:
        raise RuntimeError("Set AIRLOCK_OPERATOR_TOKEN to a random token of at least 32 characters.")
    operator_hash = token_hash(operator_token)
    workspace = PurePosixPath(os.environ.get("AIRLOCK_WORKSPACE_ROOT", "/home/agent/work"))
    if not workspace.is_absolute() or ".." in workspace.parts or workspace.anchor != "/" or not workspace.name:
        raise RuntimeError("AIRLOCK_WORKSPACE_ROOT must be an absolute sandbox workspace path.")
    sandbox_url = os.environ.get("AIRLOCK_SANDBOX_URL", "").rstrip("/")
    sandbox_key = os.environ.get("SANDBOX_API_KEY", "")
    if sandbox_url and not sandbox_key:
        raise RuntimeError("Set SANDBOX_API_KEY when AIRLOCK_SANDBOX_URL is configured.")
    store = Store(Path(os.environ.get("AIRLOCK_DB", "data/airlock.sqlite3")))
    app = FastAPI(title="AgentAirlock Guard")

    def terminate_sandbox(session_id: str) -> Literal["disabled", "terminated", "pending"]:
        if not sandbox_url:
            return "disabled"
        try:
            response = httpx.delete(
                f"{sandbox_url}/sessions/{session_id}",
                headers={"Authorization": f"Bearer {sandbox_key}"},
                timeout=2, trust_env=False, follow_redirects=False,
            )
            if response.status_code in {204, 404}:
                return "terminated"
        except httpx.HTTPError:
            pass
        log.warning("Sandbox termination is pending for session %s", session_id)
        return "pending"

    def require_operator(digest: Annotated[str, Depends(bearer_hash)]):
        if not hmac.compare_digest(digest, operator_hash):
            raise HTTPException(403, "Operator access required.")

    def session_status(db, session_id: str, digest: str | None = None) -> str:
        row = db.execute("SELECT status, sensor_token_hash FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if digest is not None and (row is None or not hmac.compare_digest(digest, row["sensor_token_hash"])):
            raise HTTPException(403, "Sensor access denied for this session.")
        if row is None:
            raise HTTPException(404, "Session not found.")
        return row["status"]

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _error):
        return JSONResponse({"detail": "Invalid request."}, status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def database_error(_request, _error):
        return JSONResponse({"detail": "Guard history is unavailable."}, status_code=503)

    @app.get("/healthz")
    def healthz():
        with closing(store.connect()) as db:
            db.execute("SELECT 1 FROM sessions LIMIT 1").fetchone()
        return {"ok": True}

    @app.post("/sessions", status_code=201, dependencies=[Depends(require_operator)])
    def create_session(body: CreateSession | None = None):
        session_id = body.session_id if body and body.session_id else uuid4().hex
        token = secrets.token_urlsafe(32)
        with store.write() as db:
            if db.execute("SELECT 1 FROM sessions WHERE id = ?", (session_id,)).fetchone():
                raise HTTPException(409, "This session is already registered.")
            db.execute("INSERT INTO sessions VALUES (?, ?, 'ACTIVE')", (session_id, token_hash(token)))
        return {"session_id": session_id, "status": "ACTIVE", "sensor_token": token}

    @app.post("/decide")
    def decide_action(request: DecideRequest, digest: Annotated[str, Depends(bearer_hash)]):
        session_id = request.session_id
        with store.write() as db:
            stopped = session_status(db, session_id, digest) == "KILLED"
            verdict = SESSION_KILLED if stopped else decide(request, store.evidence(db, session_id), workspace)
            newly_stopped = not stopped and verdict.decision == "stop"
            if newly_stopped:
                db.execute("UPDATE sessions SET status = 'KILLED' WHERE id = ?", (session_id,))
            details = {"channel": request.channel, "op": request.op, "target": request.target, **asdict(verdict)}
            if request.op == "ReadFile" and verdict.decision == "allow":
                trust, sensitivity = file_labels(request.target, request.origin)
                details.update(trust=trust, sensitivity=sensitivity)
            decision_id = store.append(db, session_id, "decision", details)
        response = {"decision_id": decision_id, **asdict(verdict)}
        if newly_stopped:
            response["sandbox_termination"] = terminate_sandbox(session_id)
        return JSONResponse(response, status_code=403 if stopped else 200)

    @app.post("/results", status_code=201)
    def record_result(result: ToolResult, digest: Annotated[str, Depends(bearer_hash)]):
        session_id = result.session_id
        with store.write() as db:
            status = session_status(db, session_id, digest)
            if status == "KILLED" and result.released_data:
                raise HTTPException(403, "The session is stopped. Withhold the tool output.")
            row = db.execute(
                "SELECT details FROM events WHERE id = ? AND session_id = ? AND kind = 'decision'",
                (result.decision_id, session_id),
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Decision not found in this session.")
            decision = json.loads(row["details"])
            if decision["decision"] != "allow":
                raise HTTPException(409, "The action was denied.")
            if result.released_data and decision["op"] != "ReadFile":
                raise HTTPException(422, "Only supported reads can release labeled data.")
            details = {"outcome": result.outcome, "released_data": result.released_data}
            existing = db.execute(
                "SELECT id, details FROM events WHERE session_id = ? AND decision_id = ?",
                (session_id, result.decision_id),
            ).fetchone()
            if existing is not None:
                if json.loads(existing["details"]) != details:
                    raise HTTPException(409, "A different result is already recorded for this decision.")
                return {"result_id": existing["id"]}
            result_id = store.append(
                db, session_id, "result", details, decision_id=result.decision_id,
                trust=decision["trust"] if result.released_data else None,
                sensitivity=decision["sensitivity"] if result.released_data else None,
            )
        return {"result_id": result_id}

    @app.get("/sessions/{session_id}/history", dependencies=[Depends(require_operator)])
    def history(session_id: str, after: Annotated[int, Query(ge=0)] = 0,
                limit: Annotated[int, Query(ge=1, le=500)] = 100):
        with closing(store.connect()) as db:
            db.execute("BEGIN")
            status = session_status(db, session_id)
            rows = db.execute(
                """SELECT id, kind, decision_id, timestamp, details, trust, sensitivity FROM events
                   WHERE session_id = ? AND id > ? ORDER BY id LIMIT ?""",
                (session_id, after, limit),
            ).fetchall()
        events = [{**dict(row), "details": json.loads(row["details"])} for row in rows]
        return {"session_id": session_id, "status": status, "events": events}

    @app.post("/sessions/{session_id}/stop", dependencies=[Depends(require_operator)])
    def stop_session(session_id: str):
        with store.write() as db:
            if session_status(db, session_id) == "ACTIVE":
                db.execute("UPDATE sessions SET status = 'KILLED' WHERE id = ?", (session_id,))
                store.append(db, session_id, "stop", {"rule": "operator_stop", "reason": "The operator stopped the session."})
        return {"session_id": session_id, "status": "KILLED", "sandbox_termination": terminate_sandbox(session_id)}

    return app
