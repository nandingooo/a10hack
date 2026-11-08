"""API tests with a fake manager (no Docker needed). Run: pytest sandbox"""

import os
import sys

os.environ["SANDBOX_API_KEY"] = "test-key"
sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import api  # noqa: E402
from manager import SandboxInfo  # noqa: E402


class FakeManager:
    def __init__(self):
        self.sessions = {}

    def create(self, session_id, env=None, agents=None):
        if agents is not None and agents > 32:
            raise ValueError("agents must be between 1 and 32")
        info = SandboxInfo(session_id, "cid", f"a10-sbx-{session_id}", f"a10-net-{session_id}",
                           "http://gateway:8080", f"tok-{session_id}", False)
        self.sessions[session_id] = info
        return info

    def get(self, session_id):
        if session_id not in self.sessions:
            return None
        return {"session_id": session_id, "container": f"a10-sbx-{session_id}", "status": "running"}

    def list(self):
        return [self.get(s) for s in self.sessions]

    def destroy(self, session_id):
        self.sessions.pop(session_id, None)

    def touch(self, session_id):
        self.touched = session_id

    def reap(self, max_age=None, idle_timeout=None):
        return [{"session_id": s, "reason": "test"} for s in list(self.sessions)]

    def created_at(self, session_id):
        return 1700000000.0 if session_id in self.sessions else None

    def resolve_token(self, token):
        return next((s for s, i in self.sessions.items() if i.session_token == token), None)


AUTH = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client():
    fake = FakeManager()
    api.app.dependency_overrides[api.get_manager] = lambda: fake
    yield TestClient(api.app)
    api.app.dependency_overrides.clear()


def test_requires_api_key(client):
    assert client.get("/sessions").status_code == 401
    assert client.get("/sessions", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/healthz").status_code == 200


def test_lifecycle(client):
    r = client.post("/sessions", json={"session_id": "s1"}, headers=AUTH)
    assert r.status_code == 201
    token = r.json()["session_token"]

    assert client.post("/sessions", json={"session_id": "s1"}, headers=AUTH).status_code == 409
    assert client.get("/sessions/s1", headers=AUTH).json()["status"] == "running"
    assert "session_token" not in client.get("/sessions/s1", headers=AUTH).json()
    assert [s["session_id"] for s in client.get("/sessions", headers=AUTH).json()] == ["s1"]

    assert client.post("/sessions/resolve", json={"token": token}, headers=AUTH).json() == \
        {"session_id": "s1", "created_at": 1700000000.0}
    assert client.post("/sessions/resolve", json={"token": "nope"}, headers=AUTH).status_code == 404

    assert client.delete("/sessions/s1", headers=AUTH).status_code == 204
    assert client.get("/sessions/s1", headers=AUTH).status_code == 404
    assert client.delete("/sessions/s1", headers=AUTH).status_code == 404


def test_generates_id_and_rejects_bad_ids(client):
    r = client.post("/sessions", json={}, headers=AUTH)
    assert r.status_code == 201 and len(r.json()["session_id"]) == 32
    assert client.post("/sessions", json={"session_id": "../x"}, headers=AUTH).status_code == 422
    assert client.get("/sessions/bad..id", headers=AUTH).status_code == 422


def test_touch_and_reap(client):
    client.post("/sessions", json={"session_id": "s1"}, headers=AUTH)
    assert client.post("/sessions/s1/touch", headers=AUTH).status_code == 204
    assert client.post("/sessions/nope/touch", headers=AUTH).status_code == 404
    assert client.post("/reap", headers=AUTH).json() == [{"session_id": "s1", "reason": "test"}]


def test_agents_sizing(client):
    assert client.post("/sessions", json={"session_id": "big", "agents": 20}, headers=AUTH).status_code == 201
    assert client.post("/sessions", json={"agents": 0}, headers=AUTH).status_code == 422
    assert client.post("/sessions", json={"agents": 99}, headers=AUTH).status_code == 422


def test_limits_for():
    from manager import SandboxConfig
    cfg = SandboxConfig()
    assert cfg.limits_for(None)["mem_limit"] == cfg.mem_limit
    big = cfg.limits_for(20)
    assert big == {"mem_limit": f"{cfg.base_mem_mb + 20 * cfg.per_agent_mem_mb}m", "cpus": min(cfg.max_cpus, 10.0),
                   "pids_limit": 704, "tmpfs_size": "224m"}
    with pytest.raises(ValueError):
        cfg.limits_for(cfg.max_agents + 1)
