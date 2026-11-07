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

    def create(self, session_id, env=None):
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

    assert client.post("/sessions/resolve", json={"token": token}, headers=AUTH).json() == {"session_id": "s1"}
    assert client.post("/sessions/resolve", json={"token": "nope"}, headers=AUTH).status_code == 404

    assert client.delete("/sessions/s1", headers=AUTH).status_code == 204
    assert client.get("/sessions/s1", headers=AUTH).status_code == 404
    assert client.delete("/sessions/s1", headers=AUTH).status_code == 404


def test_generates_id_and_rejects_bad_ids(client):
    r = client.post("/sessions", json={}, headers=AUTH)
    assert r.status_code == 201 and len(r.json()["session_id"]) == 32
    assert client.post("/sessions", json={"session_id": "../x"}, headers=AUTH).status_code == 422
    assert client.get("/sessions/bad..id", headers=AUTH).status_code == 422
