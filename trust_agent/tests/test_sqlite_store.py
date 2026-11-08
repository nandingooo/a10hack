"""Tests for SqliteStore: persistence, graph trace_back, cross-agent lineage,
and the William-compatible evidence()/kill helpers."""
import time

from provenance import (
    ActionProps, Channel, ContextEntry, Kind, Labels, Op, Sensitivity, Trust,
)
from provenance.sqlite_store import SqliteStore

_seq = 0


def entry(session, op, target, trust, sens, kind, bait=False):
    global _seq
    _seq += 1
    return ContextEntry(
        id=f"{session}:e{_seq}", ts=time.time(), session_id=session, kind=kind,
        channel=Channel.HOOK, op=op, target=target, origin="x",
        labels=Labels(trust, sens, bait=bait),
        action_props=ActionProps(is_exit=(op == Op.NETWORK_REQUEST)) if kind == Kind.ACTION else None,
    )


def read(session, target, trust=Trust.TRUSTED, sens=Sensitivity.PUBLIC, bait=False):
    return entry(session, Op.READ_FILE, target, trust, sens,
                 Kind.SECRET if sens == Sensitivity.SECRET else Kind.SOURCE, bait)


def write(session, target):
    return entry(session, Op.WRITE_FILE, target, Trust.TRUSTED, Sensitivity.PUBLIC, Kind.ACTION)


def net(session, host):
    return entry(session, Op.NETWORK_REQUEST, host, Trust.UNTRUSTED, Sensitivity.PUBLIC, Kind.ACTION)


def test_untrusted_then_exit_traced():
    s = SqliteStore(":memory:")
    s.append(read("s", "/repo/vendor/x.md", trust=Trust.UNTRUSTED))
    a = net("s", "evil.example")
    s.append(a)
    assert s.aggregate("s", a).reached_untrusted


def test_laundering_through_file():
    s = SqliteStore(":memory:")
    s.append(read("s", "/repo/vendor/x.md", trust=Trust.UNTRUSTED))
    s.append(write("s", "/repo/notes.txt"))
    s.append(read("s", "/repo/notes.txt"))
    a = net("s", "evil.example")
    s.append(a)
    agg = s.aggregate("s", a)
    assert agg.reached_untrusted and agg.confidence < 1.0


def test_cross_agent_shared_file():
    s = SqliteStore(":memory:")
    s.append(read("A", "/shared/vendor/x.md", trust=Trust.UNTRUSTED))
    s.append(write("A", "/shared/pipe.txt"))
    s.append(read("B", "/shared/pipe.txt"))     # global producer -> cross-session edge
    a = net("B", "evil.example")
    s.append(a)
    assert s.aggregate("B", a).reached_untrusted


def test_evidence_is_william_compatible():
    s = SqliteStore(":memory:")
    s.append(read("s", "/repo/src/app.py"))                       # trusted
    u = s.append(read("s", "/repo/vendor/x.md", trust=Trust.UNTRUSTED))
    sec = s.append(read("s", "/repo/.env", sens=Sensitivity.SECRET))
    untrusted_id, secret_id = s.evidence("s")
    assert untrusted_id == u and secret_id == sec


def test_kill_and_persistence(tmp_path):
    db = str(tmp_path / "airlock.db")
    s = SqliteStore(db)
    s.append(read("s", "/repo/vendor/x.md", trust=Trust.UNTRUSTED))
    s.kill("s")
    assert s.is_killed("s")
    s.close()
    # reopen: data + kill status survive
    s2 = SqliteStore(db)
    assert s2.is_killed("s")
    assert len(s2.get_entries("s")) == 1
    assert s2.get_entries("s")[0].labels.effective_trust == Trust.UNTRUSTED


def test_sessions_isolated():
    s = SqliteStore(":memory:")
    s.append(read("s1", "/repo/vendor/x.md", trust=Trust.UNTRUSTED))
    a = net("s2", "evil.example")
    s.append(a)
    assert not s.aggregate("s2", a).reached_untrusted
