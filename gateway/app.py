"""Gateway placeholder. Every read and every outbound request from a sandbox goes through here.

Agents (inside sandboxes) call, with `Authorization: Bearer $SESSION_TOKEN`:
  GET  /tools/list_files
  POST /tools/read_file   {"path": "notes/plan.md"}
  POST /tools/fetch_url   {"url": "https://..."}            outbound; the page is read as untrusted
  POST /tools/send        {"url": "https://...", "body": ".."}  outbound
  POST /tools/action      {"kind": "delete" | "credentials" | "permissions" | ..., "target": ".."}

Dashboard / admin (with `Authorization: Bearer $GATEWAY_ADMIN_KEY`):
  GET  /admin/sessions               session tags and counts
  GET  /admin/sessions/{id}/events   every read, action and decision
  GET  /admin/alerts

Config (env):
  SANDBOX_API_URL, SANDBOX_API_KEY  resolve session tokens via the sandbox API
  FILES_DIR                          workspace root (default /data/files), tags in FILES_DIR/../tags.json
  APPROVED_DESTINATIONS              JSON {"host": "public|sensitive|secret"}
  RISK_URL                           optional risk layer; can only make decisions stricter
  OFFLINE=1                          simulate fetch/send (default; demo uses made-up hosts). OFFLINE=0
                                     sends for real, pinned to the vetted IP (see egress.py)
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from pathlib import Path

import ipaddress

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

import classifier
from egress import Checked, check_destination, pinned_request
from policy import WEB_CONTENT, Decision, SessionState, decide_action, decide_egress, normalize_tags, stricter

log = logging.getLogger("gateway")
logging.basicConfig(level=logging.INFO, format="%(message)s")

FILES_DIR = Path(os.getenv("FILES_DIR", "/data/files")).resolve()
TAGS_FILE = Path(os.getenv("TAGS_FILE", str(FILES_DIR.parent / "tags.json")))
SANDBOX_API_URL = os.getenv("SANDBOX_API_URL", "http://host.docker.internal:9000")
SANDBOX_API_KEY = os.getenv("SANDBOX_API_KEY", "")
ADMIN_KEY = os.getenv("GATEWAY_ADMIN_KEY") or secrets.token_urlsafe(16)
APPROVED = json.loads(os.getenv("APPROVED_DESTINATIONS", "{}"))
RISK_URL = os.getenv("RISK_URL")
OFFLINE = os.getenv("OFFLINE", "1") == "1"
MAX_READ_BYTES = 256 * 1024

if not os.getenv("GATEWAY_ADMIN_KEY"):
    log.warning("GATEWAY_ADMIN_KEY not set; generated one for this run: %s", ADMIN_KEY)

app = FastAPI(title="a10 gateway (placeholder)", docs_url=None, redoc_url=None, openapi_url=None)


def _host_side_subnet() -> list[ipaddress.IPv4Network]:
    """Subnet of the gateway's default-route interface (the Docker bridge the host reaches
    us through). Session networks are attached later on other interfaces and never carry
    the default route, so sandboxes are never in this subnet."""
    try:
        rows = [line.split() for line in open("/proc/net/route").read().splitlines()[1:]]
    except OSError:
        return [ipaddress.ip_network("127.0.0.0/8")]
    le = lambda h: str(ipaddress.IPv4Address(int(h, 16).to_bytes(4, "little")))  # noqa: E731
    default_if = next((r[0] for r in rows if r[1] == "00000000"), None)
    nets = [ipaddress.ip_network(f"{le(r[1])}/{le(r[7])}") for r in rows
            if r[0] == default_if and r[1] != "00000000"]
    return nets or [ipaddress.ip_network("127.0.0.0/8")]


# ADMIN_SOURCES: "auto" (host side only), "any" (tests), or comma-separated CIDRs.
_admin_sources = os.getenv("ADMIN_SOURCES", "auto")
ADMIN_NETS = None if _admin_sources == "any" else (
    _host_side_subnet() if _admin_sources == "auto"
    else [ipaddress.ip_network(c.strip()) for c in _admin_sources.split(",")])
log.info("admin API accepted from: %s", ADMIN_NETS or "anywhere")

# In-memory stores. Josh's storage replaces these.
sessions: dict[str, SessionState] = {}
events: dict[str, list[dict]] = {}
alerts: list[dict] = []
_token_cache: dict[str, str] = {}


# ---------- identity ----------

def resolve_token(token: str) -> str | None:
    if token in _token_cache:
        return _token_cache[token]
    try:
        r = httpx.post(f"{SANDBOX_API_URL}/sessions/resolve", json={"token": token},
                       headers={"Authorization": f"Bearer {SANDBOX_API_KEY}"}, timeout=3)
    except httpx.HTTPError as e:
        log.error("sandbox API unreachable: %s", e)
        raise HTTPException(503, "cannot verify session")
    if r.status_code != 200:
        return None
    _token_cache[token] = r.json()["session_id"]
    return _token_cache[token]


def session(authorization: str = Header("")) -> SessionState:
    token = authorization.removeprefix("Bearer ").strip()
    session_id = resolve_token(token) if token else None
    if not session_id:
        raise HTTPException(401, "unknown session token")
    return sessions.setdefault(session_id, SessionState(session_id))


def admin(request: Request, authorization: str = Header("")) -> None:
    if ADMIN_NETS is not None:
        try:
            src = ipaddress.ip_address(request.client.host)
        except ValueError:
            raise HTTPException(403, "admin API not reachable from here")
        if not any(src in n for n in ADMIN_NETS):
            raise HTTPException(403, "admin API not reachable from here")
    if not secrets.compare_digest(authorization.removeprefix("Bearer ").strip(), ADMIN_KEY):
        raise HTTPException(401, "admin key required")


# ---------- logging, risk layer ----------

def record(state: SessionState, kind: str, detail: dict, decision: Decision | None = None) -> dict:
    ev = {"ts": time.time(), "session_id": state.session_id, "kind": kind, **detail,
          "session_tags": state.tags()}
    if decision:
        ev.update(decision=decision.decision, rule=decision.rule, reason=decision.reason)
        if decision.alert:
            alerts.append(ev)
    events.setdefault(state.session_id, []).append(ev)
    log.info(json.dumps(ev))
    return ev


def with_risk(state: SessionState, kind: str, detail: dict, d: Decision) -> Decision:
    """Ask the risk layer; it can only make the decision stricter. Errors keep the rule decision."""
    if not RISK_URL:
        return d
    try:
        r = httpx.post(RISK_URL, timeout=0.5, json={
            "session_id": state.session_id, "action": kind, "args": detail,
            "session_tags": state.tags(), "recent_events": events.get(state.session_id, [])[-20:],
        })
        risk = r.json()["decision"]
    except Exception as e:  # noqa: BLE001
        log.warning("risk layer unavailable, keeping rule decision: %s", e)
        return d
    if stricter(risk, d.decision) != d.decision:
        return Decision(risk, "risk-layer", r.json().get("reason", "risk layer"), alert=risk == "block")
    return d


# Outbound client for agent traffic: ignores proxy env vars; connects only to vetted IPs.
_egress = httpx.Client(timeout=10, trust_env=False)


def guard_destination(state: SessionState, kind: str, url: str) -> Checked:
    """R0: the gateway never reaches internal addresses on an agent's behalf."""
    checked = check_destination(url, offline=OFFLINE)
    if checked.reason:
        d = Decision("block", "R0-internal-destination", checked.reason, alert=True)
        record(state, kind, {"url": url, "destination": checked.host}, d)
        enforce(d)
    return checked


def egress(method: str, url: str, checked: Checked, **kw) -> tuple[int, dict, bytes]:
    try:
        return pinned_request(_egress, method, url, checked, MAX_READ_BYTES, **kw)
    except (httpx.HTTPError, ValueError) as e:
        raise HTTPException(502, f"upstream request failed: {type(e).__name__}: {e}")


def screen(state: SessionState, kind: str, source: str, content: str, tags: dict) -> dict:
    """Prompt Guard on content the agent is about to see. A hit can only lower trust to
    'untrusted' (R1/R3 then block); it never blocks the read itself and never raises trust."""
    v = classifier.check(content)
    if v is None or not v.flagged:
        return tags
    d = Decision("allow", "PG-injection",
                 f"prompt guard score {v.score:.2f} >= {classifier.THRESHOLD}; read treated as untrusted",
                 alert=True)
    record(state, "prompt_guard", {"source_kind": kind, "source": source, "score": v.score,
                                   "hidden_parts": v.hidden_parts, "tags_before": tags}, d)
    return {**tags, "trust": "untrusted"}


def enforce(d: Decision) -> None:
    if d.decision == "block":
        raise HTTPException(403, {"decision": "block", "rule": d.rule, "reason": d.reason})
    if d.decision == "ask":
        # Placeholder: no approval queue yet, so "ask" is held as a denial.
        raise HTTPException(403, {"decision": "ask", "rule": d.rule,
                                  "reason": d.reason + " (approval flow not implemented yet)"})


# ---------- files ----------

def load_tags() -> dict:
    try:
        return json.loads(TAGS_FILE.read_text())
    except (OSError, ValueError):
        return {}


def safe_path(rel: str) -> Path:
    p = (FILES_DIR / rel).resolve()
    if p != FILES_DIR and FILES_DIR not in p.parents:
        raise HTTPException(400, "path outside workspace")
    return p


# ---------- agent tools ----------

class ReadFile(BaseModel):
    path: str


class Fetch(BaseModel):
    url: str


class Send(BaseModel):
    url: str
    body: str = ""


class Action(BaseModel):
    kind: str
    target: str = ""


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/tools/list_files")
def list_files(state: SessionState = Depends(session)):
    files = sorted(str(p.relative_to(FILES_DIR)) for p in FILES_DIR.rglob("*") if p.is_file())
    record(state, "list_files", {"count": len(files)})
    return {"files": files}


@app.post("/tools/read_file")
def read_file(body: ReadFile, state: SessionState = Depends(session)):
    p = safe_path(body.path)
    if not p.is_file():
        raise HTTPException(404, "no such file")
    rel = str(p.relative_to(FILES_DIR))
    content = p.read_bytes()[:MAX_READ_BYTES].decode(errors="replace")
    tags = screen(state, "read_file", rel, content, normalize_tags(load_tags().get(rel)))
    state.absorb(f"file:{rel}", tags)
    if tags["bait"]:
        d = Decision("allow", "R4-bait", "DECOY READ: nothing may leave this session now", alert=True)
    else:
        d = Decision("allow", "read", "reads are allowed; tags applied to session")
    record(state, "read_file", {"path": rel, "file_tags": tags}, d)
    return {"path": rel, "content": content}


@app.post("/tools/fetch_url")
def fetch_url(body: Fetch, state: SessionState = Depends(session)):
    checked = guard_destination(state, "fetch_url", body.url)
    d = with_risk(state, "fetch_url", {"url": body.url}, decide_egress(state, checked.host, APPROVED))
    record(state, "fetch_url", {"url": body.url, "destination": checked.host, "ip": (checked.addrs or [None])[0]}, d)
    enforce(d)
    if OFFLINE:
        return_ = {"url": body.url, "status": 200, "content": f"[offline placeholder for {body.url}]"}
    else:
        status, hdrs, raw = egress("GET", body.url, checked)
        return_ = {"url": body.url, "status": status, "content": raw.decode(errors="replace")}
        if "location" in hdrs:
            return_["redirect_to"] = hdrs["location"]  # not followed; fetching it is re-checked
    state.absorb(f"url:{body.url}", screen(state, "fetch_url", body.url, return_["content"], WEB_CONTENT))
    return return_


@app.post("/tools/send")
def send(body: Send, state: SessionState = Depends(session)):
    checked = guard_destination(state, "send", body.url)
    d = with_risk(state, "send", {"url": body.url, "bytes": len(body.body)},
                  decide_egress(state, checked.host, APPROVED))
    record(state, "send", {"url": body.url, "destination": checked.host, "bytes": len(body.body)}, d)
    enforce(d)
    if OFFLINE:
        return {"sent": True, "offline": True}
    status, _, _ = egress("POST", body.url, checked, content=body.body.encode())
    return {"sent": True, "offline": False, "status": status}


@app.post("/tools/action")
def action(body: Action, state: SessionState = Depends(session)):
    d = with_risk(state, "action", {"action": body.kind, "target": body.target},
                  decide_action(state, body.kind))
    record(state, "action", {"action": body.kind, "target": body.target}, d)
    enforce(d)
    return {"done": True, "note": "placeholder: no real action performed"}


# ---------- dashboard / admin ----------

@app.get("/admin/sessions", dependencies=[Depends(admin)])
def admin_sessions():
    return [{**s.tags(), "session_id": s.session_id, "reads": len(s.reads),
             "events": len(events.get(s.session_id, []))} for s in sessions.values()]


@app.get("/admin/sessions/{session_id}/events", dependencies=[Depends(admin)])
def admin_events(session_id: str):
    return events.get(session_id, [])


@app.get("/admin/alerts", dependencies=[Depends(admin)])
def admin_alerts():
    return alerts


classifier.warm()  # no-op unless PROMPT_GUARD=1

# Model API proxy and MCP server register their routes on `app`.
import llm  # noqa: E402,F401
import mcp  # noqa: E402,F401
