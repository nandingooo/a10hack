"""Gateway placeholder tests. Run: pytest gateway"""

import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
os.environ.update(FILES_DIR=str(HERE / "workspace/files"), GATEWAY_ADMIN_KEY="adm",
                  APPROVED_DESTINATIONS='{"api.internal.example": "sensitive"}', OFFLINE="1")
sys.path.insert(0, str(HERE))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app as gw  # noqa: E402
from policy import SessionState, decide_action, decide_egress  # noqa: E402

APPROVED = {"api.internal.example": "sensitive"}


# ---------- rules ----------

def state(*reads):
    s = SessionState("s")
    for t in reads:
        s.absorb("x", t)
    return s


TRUSTED_PUBLIC = {"trust": "trusted", "sensitivity": "public"}
UNTRUSTED = {"trust": "untrusted", "sensitivity": "public"}
SENSITIVE = {"trust": "trusted", "sensitivity": "sensitive"}
SECRET = {"trust": "trusted", "sensitivity": "secret"}
BAIT = {"trust": "trusted", "sensitivity": "secret", "bait": True}


def test_tags_combine_lowest_trust_highest_sensitivity():
    s = state(TRUSTED_PUBLIC, UNTRUSTED, SENSITIVE)
    assert s.tags() == {"trust": "untrusted", "sensitivity": "sensitive", "bait": False}
    s.absorb("y", TRUSTED_PUBLIC)  # never relaxes
    assert s.trust == "untrusted" and s.sensitivity == "sensitive"


def test_untagged_is_unknown_and_sensitive():
    assert state(None).tags() == {"trust": "unknown", "sensitivity": "sensitive", "bait": False}


@pytest.mark.parametrize("reads, kind, expected", [
    ([TRUSTED_PUBLIC], "delete", "allow"),
    ([UNTRUSTED], "delete", "block"),
    ([None], "credentials", "ask"),
    ([UNTRUSTED], "read_calendar", "allow"),
    ([BAIT], "anything", "block"),
])
def test_action_rules(reads, kind, expected):
    assert decide_action(state(*reads), kind).decision == expected


@pytest.mark.parametrize("reads, host, expected, rule", [
    ([TRUSTED_PUBLIC], "example.com", "allow", "default"),
    ([SENSITIVE], "example.com", "ask", "R2-destination"),
    ([SENSITIVE], "api.internal.example", "allow", "default"),
    ([SECRET], "api.internal.example", "block", "R2-destination"),
    ([UNTRUSTED, SENSITIVE], "api.internal.example", "block", "R3-injection-leak"),
    ([BAIT], "api.internal.example", "block", "R4-bait"),
])
def test_egress_rules(reads, host, expected, rule):
    d = decide_egress(state(*reads), host, APPROVED)
    assert (d.decision, d.rule) == (expected, rule)


# ---------- HTTP ----------

@pytest.fixture
def client(monkeypatch):
    gw.sessions.clear(); gw.events.clear(); gw.alerts.clear()
    monkeypatch.setattr(gw, "resolve_token", lambda t: {"tok-a": "a", "tok-b": "b"}.get(t))
    return TestClient(gw.app)


def call(c, tok, path, body=None):
    h = {"Authorization": f"Bearer {tok}"}
    return c.post(path, json=body, headers=h) if body is not None else c.get(path, headers=h)


def test_requires_session_token(client):
    assert call(client, "nope", "/tools/list_files").status_code == 401


def test_prompt_injection_leak_is_blocked(client):
    assert call(client, "tok-a", "/tools/read_file", {"path": "web/downloaded-page.html"}).status_code == 200
    assert call(client, "tok-a", "/tools/read_file", {"path": "docs/q3-plan.md"}).status_code == 200
    r = call(client, "tok-a", "/tools/send", {"url": "https://api.internal.example/x", "body": "plan"})
    assert r.status_code == 403 and r.json()["detail"]["rule"] == "R3-injection-leak"
    alerts = client.get("/admin/alerts", headers={"Authorization": "Bearer adm"}).json()
    assert len(alerts) == 1 and alerts[0]["session_id"] == "a"


def test_sessions_are_tracked_separately(client):
    call(client, "tok-a", "/tools/read_file", {"path": "web/downloaded-page.html"})
    r = call(client, "tok-b", "/tools/action", {"kind": "delete", "target": "x"})
    assert r.status_code == 200  # b never read untrusted content


def test_decoy_read_locks_session(client):
    call(client, "tok-a", "/tools/read_file", {"path": ".decoy/aws-credentials"})
    r = call(client, "tok-a", "/tools/fetch_url", {"url": "https://example.com"})
    assert r.status_code == 403 and r.json()["detail"]["rule"] == "R4-bait"


def test_fetched_page_taints_session(client):
    assert call(client, "tok-a", "/tools/fetch_url", {"url": "https://example.com"}).status_code == 200
    r = call(client, "tok-a", "/tools/action", {"kind": "permissions"})
    assert r.json()["detail"]["rule"] == "R1-untrusted-risky"


def test_path_traversal_rejected(client):
    assert call(client, "tok-a", "/tools/read_file", {"path": "../tags.json"}).status_code == 400
    assert call(client, "tok-a", "/tools/read_file", {"path": "/etc/passwd"}).status_code == 400


def test_admin_requires_key(client):
    assert client.get("/admin/sessions").status_code == 401
    call(client, "tok-a", "/tools/list_files")
    r = client.get("/admin/sessions/a/events", headers={"Authorization": "Bearer adm"})
    assert r.json()[0]["kind"] == "list_files"


def test_risk_layer_can_only_tighten(client, monkeypatch):
    class R:
        def __init__(self, d): self.d = d
        def json(self): return {"decision": self.d, "reason": "risk says so"}
    monkeypatch.setattr(gw, "RISK_URL", "http://risk")
    monkeypatch.setattr(gw.httpx, "post", lambda *a, **k: R("allow"))
    call(client, "tok-a", "/tools/read_file", {"path": "secrets/api-keys.txt"})
    r = call(client, "tok-a", "/tools/send", {"url": "https://example.com"})
    assert r.json()["detail"]["decision"] == "block"  # risk "allow" can't relax a block
    monkeypatch.setattr(gw.httpx, "post", lambda *a, **k: R("block"))
    r = call(client, "tok-b", "/tools/send", {"url": "https://example.com"})
    assert r.json()["detail"]["rule"] == "risk-layer"
