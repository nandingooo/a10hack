"""Unit tests for the tagging + storage/aggregation module.

Covers the labeler and the QueueStore aggregation. These assert the
``Aggregate`` output (this module's responsibility); P1 owns the final
verdict tests (AGENTS.md section 11). A strict-xfail test proves the
TreeStore interface is wired and ready for the queue->tree upgrade.
"""
import time

import pytest

from provenance import (
    ActionProps, Channel, ContextEntry, Kind, Labeler, Labels, Op, Policy,
    QueueStore, Sensitivity, Trust,
)


def make_policy() -> Policy:
    return Policy(
        trusted_origins=["user", "operator"],
        untrusted_origins=["cloned-repo", "web", "tool-output", "download"],
        secret_globs=["**/.env", "**/.aws/credentials", "**/.ssh/*"],
        sensitive_globs=["**/config/*"],
        bait_files=["**/aws_prod_credentials.txt"],
        bait_token="AKIA_FAKE_BAIT_DO_NOT_USE",
        approved_hosts=["github.com", "pypi.org"],
        workspace_root="/work",
    )


@pytest.fixture
def lab() -> Labeler:
    return Labeler(make_policy())


@pytest.fixture
def store() -> QueueStore:
    return QueueStore()


_counter = 0


def entry(session, op, target, origin, labels, kind=Kind.SOURCE, action_props=None):
    global _counter
    _counter += 1
    return ContextEntry(
        id=f"e{_counter}", ts=time.time(), session_id=session, kind=kind,
        channel=Channel.HOOK, op=op, target=target, origin=origin,
        labels=labels, action_props=action_props,
    )


def net_action(session, host="evil.example"):
    return entry(
        session, Op.NETWORK_REQUEST, host, "workspace",
        Labels(Trust.TRUSTED, Sensitivity.PUBLIC, in_workspace=False),
        kind=Kind.ACTION, action_props=ActionProps(is_exit=True),
    )


# ---------------- labeler ----------------

def test_label_trusted_public(lab):
    lbl = lab.label("/work/src/app.py", "user")
    assert lbl.trust == Trust.TRUSTED
    assert lbl.sensitivity == Sensitivity.PUBLIC


def test_label_untrusted_from_cloned_repo(lab):
    assert lab.label("/work/README.md", "cloned-repo").trust == Trust.UNTRUSTED


def test_unknown_origin_is_untrusted(lab):
    assert lab.label("/work/x", "mystery-origin").effective_trust == Trust.UNTRUSTED


def test_label_secret(lab):
    assert lab.label("/work/.env", "user").sensitivity == Sensitivity.SECRET


def test_label_bait(lab):
    assert lab.label("/work/aws_prod_credentials.txt", "workspace").bait is True


def test_bait_token_in_body(lab):
    assert lab.is_bait_target("NetworkRequest", "evil.example", "x=AKIA_FAKE_BAIT_DO_NOT_USE")


def test_approved_host(lab):
    assert lab.approved_host("github.com")
    assert not lab.approved_host("evil.example")


# ---------------- aggregation (QueueStore) ----------------

def test_empty_session_is_clean(store):
    action = net_action("s")
    store.append(action)
    agg = store.aggregate("s", action)
    assert not agg.reached_untrusted and not agg.reached_secret and not agg.reached_bait


def test_untrusted_read_then_action(store, lab):
    store.append(entry("s", Op.READ_FILE, "/work/README.md", "cloned-repo",
                       lab.label("/work/README.md", "cloned-repo")))
    action = net_action("s")
    store.append(action)
    agg = store.aggregate("s", action)
    assert agg.reached_untrusted and not agg.reached_secret
    assert len(agg.supporting_entry_ids) >= 1


def test_secret_read_reached(store, lab):
    store.append(entry("s", Op.READ_FILE, "/work/.env", "user",
                       lab.label("/work/.env", "user"), kind=Kind.SECRET))
    action = net_action("s")
    store.append(action)
    assert store.aggregate("s", action).reached_secret


def test_bait_read_reached(store, lab):
    store.append(entry("s", Op.READ_FILE, "/work/aws_prod_credentials.txt", "workspace",
                       lab.label("/work/aws_prod_credentials.txt", "workspace")))
    action = net_action("s")
    store.append(action)
    assert store.aggregate("s", action).reached_bait


def test_sessions_are_isolated(store, lab):
    # Taint in session s1 must never leak into session s2.
    store.append(entry("s1", Op.READ_FILE, "/work/README.md", "cloned-repo",
                       lab.label("/work/README.md", "cloned-repo")))
    action = net_action("s2")
    store.append(action)
    assert not store.aggregate("s2", action).reached_untrusted


def test_appends_are_not_evicted(store, lab):
    for _ in range(50):
        store.append(entry("s", Op.READ_FILE, "/work/notes.txt", "workspace",
                           lab.label("/work/notes.txt", "workspace")))
    store.append(entry("s", Op.READ_FILE, "/work/README.md", "cloned-repo",
                       lab.label("/work/README.md", "cloned-repo")))
    for _ in range(50):
        store.append(entry("s", Op.READ_FILE, "/work/more.txt", "workspace",
                           lab.label("/work/more.txt", "workspace")))
    action = net_action("s")
    store.append(action)
    # The untrusted read in the middle must still count (no sliding-window forgetting).
    assert store.aggregate("s", action).reached_untrusted


# ---------------- tree readiness ----------------

@pytest.mark.xfail(reason="TreeStore lands in the queue->tree upgrade (AGENTS.md 14)", strict=True)
def test_tree_store_interface_ready():
    from provenance.tree_store import TreeStore
    TreeStore().append(None)  # raises NotImplementedError -> xfail (proves it's wired)
