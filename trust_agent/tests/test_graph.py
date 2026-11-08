"""Tests for GraphStore: real-time DAG construction, laundering detection, and
precision (no over-blocking) -- the advantages over the queue's session union.
"""
import time

from provenance import (
    ActionProps, Channel, ContextEntry, Kind, Labels, Op, Sensitivity, Trust,
)
from provenance.graph_store import GraphStore


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


def test_direct_untrusted_to_exit_is_reachable():
    g = GraphStore()
    r = read("s", "/repo/vendor/README.md", trust=Trust.UNTRUSTED)
    g.append(r)
    a = net("s", "evil.example")
    g.append(a)
    agg = g.aggregate("s", a)
    assert agg.reached_untrusted
    assert r.id in agg.supporting_entry_ids


def test_laundering_through_an_intermediate_file_is_caught():
    g = GraphStore()
    g.append(read("s", "/repo/vendor/README.md", trust=Trust.UNTRUSTED))  # untrusted source
    g.append(write("s", "/repo/notes.txt"))        # action: inherits the untrusted read (recency); produces notes.txt
    g.append(read("s", "/repo/notes.txt"))         # read back: file-lineage edge to the write
    a = net("s", "evil.example")                   # exfil: inherits the notes.txt read
    g.append(a)
    agg = g.aggregate("s", a)
    # trace_back: exfil -> read notes -> write notes -> README(untrusted)
    assert agg.reached_untrusted
    assert agg.confidence < 1.0                    # inferred edges, weakest hop


def test_precision_unrelated_action_not_overblocked():
    g = GraphStore()
    g.append(read("s", "/repo/vendor/README.md", trust=Trust.UNTRUSTED))  # untrusted read
    g.append(write("s", "/repo/notes.txt"))        # consumes the working set (the read)
    # a later action with NO reads feeding it must NOT inherit the earlier taint
    a = net("s", "github.com")
    g.append(a)
    agg = g.aggregate("s", a)
    assert not agg.reached_untrusted               # queue would wrongly say True here


def test_secret_reaches_exit():
    g = GraphStore()
    g.append(read("s", "/repo/.env", sens=Sensitivity.SECRET))
    a = net("s", "evil.example")
    g.append(a)
    assert g.aggregate("s", a).reached_secret


def test_sessions_isolated():
    g = GraphStore()
    g.append(read("s1", "/repo/vendor/x", trust=Trust.UNTRUSTED))
    a = net("s2", "evil.example")
    g.append(a)
    assert not g.aggregate("s2", a).reached_untrusted


def test_edges_built_incrementally_on_append():
    g = GraphStore()
    r = read("s", "/repo/notes.txt")
    g.append(r)
    assert r.parents == []                          # first read, no producer yet
    w = write("s", "/repo/out.txt")
    g.append(w)
    assert r.id in w.parents                         # the write inherited the prior read immediately
    r2 = read("s", "/repo/out.txt")
    g.append(r2)
    assert w.id in r2.parents                        # reading the produced file linked to its writer at append time


# ---- multi-agent / inter-agent provenance ----

def test_cross_agent_laundering_via_shared_file():
    g = GraphStore()
    # Agent A reads an untrusted file, then writes a shared file.
    g.append(read("A", "/shared/vendor/x.md", trust=Trust.UNTRUSTED))
    g.append(write("A", "/shared/pipe.txt"))
    # Agent B (separate session) reads that shared file, then tries to exfiltrate.
    g.append(read("B", "/shared/pipe.txt"))          # cross-session edge to A's write (global producer)
    b = net("B", "evil.example")
    g.append(b)
    agg = g.aggregate("B", b)
    # B never read the untrusted file itself, but the shared-file lineage reaches it.
    assert agg.reached_untrusted


def test_inter_agent_message_carries_taint():
    g = GraphStore()
    g.append(read("A", "/x/vendor/x.md", trust=Trust.UNTRUSTED))  # A is tainted
    g.ingest_inbound("B", "A")                        # B receives a message/delegation from A
    b = net("B", "evil.example")
    g.append(b)
    agg = g.aggregate("B", b)
    assert agg.reached_untrusted                      # taint-on-ingest: B inherits A's taint
    assert agg.confidence < 1.0                       # cross-agent edge is inferred


def test_clean_agent_message_does_not_taint():
    g = GraphStore()
    g.append(read("A", "/repo/src/app.py"))           # A only touched trusted/public
    g.ingest_inbound("B", "A")
    b = net("B", "github.com")
    g.append(b)
    agg = g.aggregate("B", b)
    assert not agg.reached_untrusted and not agg.reached_secret
