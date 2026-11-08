"""Read-mostly client for the standalone hook-mode guard (trust_agent/gateway/app/service.py).

Claude Code and Codex sessions with the TrustAgent hook installed report to this service
(AIRLOCK_URL, default http://127.0.0.1:8787). The dashboard lists them as live agents.
"""

import json
import os
import re
import threading
from collections import deque
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

DEFAULT_URL = "http://127.0.0.1:8787"
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
EVENT_CACHE_LIMIT = 2000
PAGE_SIZE = 1000
TIMEOUT_SECONDS = 3


class GatewayUnavailable(Exception):
    """The hook-mode guard did not answer (not started, crashed, or wrong token)."""


def valid_session(session: str) -> bool:
    return bool(session) and SESSION_PATTERN.fullmatch(session) is not None


class LiveGateway:
    def __init__(self, url: str | None = None, token: str | None = None):
        self.url = (url or os.environ.get("TRUSTAGENT_LOCAL_GATEWAY") or DEFAULT_URL).rstrip("/")
        self.token = token if token is not None else os.environ.get("AIRLOCK_ADMIN_TOKEN", "")
        self.lock = threading.Lock()
        self.cache: dict[str, deque] = {}

    def _call(self, path: str, data: dict | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        body = json.dumps(data).encode() if data is not None else None
        try:
            with urlopen(Request(self.url + path, body, headers), timeout=TIMEOUT_SECONDS) as response:
                return json.load(response)
        except HTTPError as error:
            raise GatewayUnavailable(f"guard answered HTTP {error.code}") from error
        except (URLError, OSError, ValueError) as error:
            raise GatewayUnavailable(str(error)) from error

    def agents(self) -> list[dict]:
        try:
            return self._call("/agents")["agents"]
        except GatewayUnavailable as error:
            if "HTTP 404" not in str(error):
                raise
        # Older guard without /agents: only configured or killed sessions are visible.
        return [dict(session_id=s["session_id"], status=s.get("status", "ACTIVE"), agent=s.get("agent", "unknown"), events=None,
                     last_ts=None, decisions=None, denials=None, managed=True, strict=False)
                for s in self._call("/sessions")["sessions"]]

    def events(self, session: str) -> list[dict]:
        """Incrementally page the append-only audit; cache so polling stays cheap."""
        with self.lock:
            cache = self.cache.setdefault(session, deque(maxlen=EVENT_CACHE_LIMIT))
            cursor = cache[-1]["seq"] if cache else 0
            while True:
                page = self._call(f"/events?session_id={quote(session, safe='')}&after={cursor}")["events"]
                if not page:
                    break
                if page[-1]["seq"] <= cursor or any(e.get("session_id") != session for e in page):
                    raise GatewayUnavailable("invalid audit stream")
                cache.extend(page)
                cursor = page[-1]["seq"]
                if len(page) < PAGE_SIZE:
                    break
            return list(cache)

    def entries(self, session: str) -> list[dict]:
        return self._call(f"/entries?session_id={quote(session, safe='')}")["entries"]

    def snapshot(self, session: str | None) -> dict:
        try:
            agents = self.agents()
        except GatewayUnavailable as error:
            return {"gateway": {"url": self.url, "ok": False, "error": str(error)}, "agents": [],
                    "agent": None, "events": [], "entries": []}
        selected = session or (agents[0]["session_id"] if agents else None)
        agent = next((a for a in agents if a["session_id"] == selected), None)
        events, entries = [], []
        if agent:
            try:
                events, entries = self.events(selected), self.entries(selected)
            except GatewayUnavailable as error:
                return {"gateway": {"url": self.url, "ok": False, "error": str(error)}, "agents": agents,
                        "agent": agent, "events": [], "entries": []}
        return {"gateway": {"url": self.url, "ok": True, "error": ""}, "agents": agents,
                "agent": agent, "events": events, "entries": entries}

    def kill(self, session: str) -> None:
        self._call("/kill", {"session_id": session})
