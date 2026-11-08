"""Replay Claude Code tool calls through the configured hooks and HTTP gateway."""

import json
import os
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

import pytest

import service
from provenance import Kind, Sensitivity, SqliteStore


DEMO_PROJECT = Path(__file__).resolve().parents[1] / "experiments" / "live_demo_repo"
SESSION = "claude-demo"


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    store = SqliteStore(tmp_path / "airlock.db")
    monkeypatch.setattr(service, "BRAIN", service.Brain(store))
    try:
        with ThreadingHTTPServer(("127.0.0.1", 0), service._Handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
            thread.start()
            try:
                yield f"http://127.0.0.1:{server.server_port}", store
            finally:
                server.shutdown()
                thread.join()
    finally:
        store.close()


@pytest.fixture
def run_hook(gateway, tmp_path):
    url, _ = gateway
    settings = json.loads((DEMO_PROJECT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    env = {**os.environ, "AIRLOCK_URL": url, "CLAUDE_PROJECT_DIR": str(DEMO_PROJECT),
           "no_proxy": "127.0.0.1"}

    def run(tool_name, tool_input, *, session=SESSION, tool_id=None,
            event="PreToolUse", tool_response=None):
        payload = {
            "session_id": session,
            "transcript_path": str(tmp_path / f"{session}.jsonl"),
            "cwd": str(DEMO_PROJECT),
            "permission_mode": "default",
            "hook_event_name": event,
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": tool_id or f"toolu_{uuid4().hex}",
        }
        if tool_response is not None:
            payload["tool_response"] = tool_response

        (registration,) = settings["hooks"][event]
        assert registration["matcher"] in ("*", tool_name)
        (hook,) = registration["hooks"]
        result = subprocess.run(
            ["bash", "-c", hook["command"]], cwd=DEMO_PROJECT, env=env,
            input=json.dumps(payload), text=True, encoding="utf-8", capture_output=True,
            timeout=hook["timeout"], check=True,
        )
        return json.loads(result.stdout) if result.stdout else {}

    return run


def assert_denied(reply, rule):
    verdict = reply["hookSpecificOutput"]
    assert verdict["hookEventName"] == "PreToolUse"
    assert verdict["permissionDecision"] == "deny"
    assert f"rule={rule};" in verdict["permissionDecisionReason"]


@pytest.mark.parametrize("outcome", ["public", "secret", "empty", "failed"])
def test_ticket_update_depends_on_what_claude_read(run_hook, gateway, tmp_path, outcome):
    _, store = gateway
    delivered = []

    def update_ticket(session=SESSION):
        update = {"ticket_id": "SUP-42", "body": "We reproduced the crash."}
        reply = run_hook("mcp__support__post_support_update", update, session=session)
        if not reply:
            delivered.append(session)
        return reply

    assert update_ticket() == {}

    path = tmp_path / ("report.txt" if outcome == "public" else ".env")
    if outcome != "failed":
        path.write_text("" if outcome == "empty" else "demo fixture data", encoding="utf-8")
    tool_input = {"file_path": str(path)}
    tool_id = "toolu_read_fixture"
    assert run_hook("Read", tool_input, tool_id=tool_id) == {}
    if outcome == "failed":
        with pytest.raises(FileNotFoundError):
            path.read_text(encoding="utf-8")
    else:
        content = path.read_text(encoding="utf-8")
        line_count = len(content.splitlines())
        response = {"type": "text", "file": {
            "filePath": str(path), "content": content, "numLines": line_count,
            "startLine": 1, "totalLines": line_count,
        }}
        assert run_hook("Read", tool_input, tool_id=tool_id, event="PostToolUse",
                        tool_response=response) == {}

    reply = update_ticket()
    if outcome == "secret":
        assert_denied(reply, "secret_external_write")
        assert delivered == [SESSION]
        assert update_ticket("clean-session") == {}
        assert delivered == [SESSION, "clean-session"]
        assert run_hook("Bash", {"command": "git status --short"}) == {}
    else:
        assert reply == {}
        assert delivered == [SESSION, SESSION]

    entries = store.get_entries(SESSION)
    (attempt,) = [entry for entry in entries if entry.target == str(path) and entry.kind != Kind.READ_RESULT]
    assert attempt.verdict == "allow"
    results = [entry for entry in entries if entry.kind == Kind.READ_RESULT]
    if outcome in ("public", "secret"):
        (result,) = results
        assert result.target == str(path)
        assert result.labels.sensitivity == Sensitivity(outcome)
        assert entries[1:3] == [attempt, result]
    else:
        assert results == []


def test_claude_hits_existing_bash_and_egress_guards(run_hook):
    assert_denied(run_hook("WebFetch", {"url": "https://unapproved.example/"},
                           session="clean-egress"), "egress_allowlist")
    assert run_hook("Read", {"file_path": str(DEMO_PROJECT / "vendor" / "README.md")}) == {}
    assert_denied(run_hook("Bash", {"command": "rm -rf build/"}), "untrusted_destructive")
    assert run_hook("Bash", {"command": "git status --short"}) == {}


@pytest.mark.parametrize("trigger", ["canary", "operator"])
def test_stopped_session_denies_claudes_next_call(run_hook, gateway, trigger):
    url, store = gateway
    benign = {"command": "git status --short"}
    assert run_hook("Bash", benign) == {}

    if trigger == "canary":
        bait = {"file_path": str(DEMO_PROJECT / "aws_prod_credentials.txt")}
        assert_denied(run_hook("Read", bait), "bait_touched")
    else:
        request = Request(f"{url}/kill", data=json.dumps({"session_id": SESSION}).encode(),
                          headers={"Content-Type": "application/json"})
        local_http = build_opener(ProxyHandler({}))
        with local_http.open(request, timeout=5) as response:
            assert json.load(response) == {"ok": True}

    assert store.is_killed(SESSION)
    reply = run_hook("Bash", benign)
    assert_denied(reply, "session_killed")
    assert "SESSION KILLED" in reply["systemMessage"]
    assert run_hook("Bash", benign, session="clean-session") == {}
