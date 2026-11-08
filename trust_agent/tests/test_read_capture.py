"""Read-capture fidelity tests for the provenance module.

These simulate a coding agent reading a stream of files during a session and
verify that the ``QueueStore`` captures every read faithfully: completeness,
order, correct per-file labels, field fidelity, no eviction at scale, session
isolation, duplicate handling, and that captured reads drive ``aggregate()``.

There is no live agent sensor yet, so an agent read is simulated as:
``label(path, origin) -> ContextEntry -> store.append(entry)``. This exercises
the capture/record/label logic, not live interception of a real agent.
"""
import itertools
import time

import pytest

from provenance import (
    Channel, ContextEntry, Kind, Labeler, Op, Policy, QueueStore,
    Sensitivity, Trust,
)

_ids = itertools.count(1)


def make_policy() -> Policy:
    """Build a Policy inline (mirrors test_provenance.py) so these tests do
    not depend on PyYAML / on-disk labels.yaml."""
    return Policy(
        trusted_origins=["user", "operator"],
        untrusted_origins=["cloned-repo", "web", "tool-output", "download"],
        secret_globs=["**/.env", "**/.aws/credentials", "**/.ssh/*",
                      "**/*token*", "**/*.pem", "**/id_rsa*"],
        sensitive_globs=["**/config/*", "**/*.log", "**/customers/*"],
        bait_files=["**/aws_prod_credentials.txt", "**/.env.production.local"],
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


def read_file(store, lab, session, path, origin,
              kind=Kind.SOURCE, op=Op.READ_FILE) -> ContextEntry:
    """Simulate the agent reading one file: label it, build a ContextEntry,
    and append it to the store. Returns the exact entry that was captured."""
    entry = ContextEntry(
        id=f"{session}:{next(_ids)}",
        ts=time.time(),
        session_id=session,
        kind=kind,
        channel=Channel.HOOK,
        op=op,
        target=path,
        origin=origin,
        labels=lab.label(path, origin),
    )
    store.append(entry)
    return entry


# A realistic ~10-read session: (path, origin, kind) as a sensor would feed it.
REALISTIC_READS = [
    ("/work/src/app.py", "user", Kind.SOURCE),
    ("/work/src/utils.py", "user", Kind.SOURCE),
    ("/work/README.md", "cloned-repo", Kind.SOURCE),
    ("/work/.env", "user", Kind.SECRET),
    ("/work/config/settings.yaml", "user", Kind.SOURCE),
    ("/work/.aws/credentials", "user", Kind.SECRET),
    ("/work/aws_prod_credentials.txt", "workspace", Kind.SOURCE),
    ("/work/.ssh/id_rsa", "user", Kind.SECRET),
    ("/work/docs/guide.md", "web", Kind.SOURCE),
    ("/work/app.log", "user", Kind.SOURCE),
]


def _read_sequence(store, lab, session, reads):
    return [read_file(store, lab, session, p, o, kind=k) for p, o, k in reads]


# ---------------- 1. completeness ----------------

def test_every_read_is_captured(store, lab):
    # Arrange / Act
    read = _read_sequence(store, lab, "sess", REALISTIC_READS)

    # Assert: none dropped.
    captured = store.get_entries("sess")
    assert len(captured) == len(REALISTIC_READS) == 10
    assert {e.id for e in captured} == {e.id for e in read}


# ---------------- 2. order preserved ----------------

def test_reads_returned_in_read_order(store, lab):
    read = _read_sequence(store, lab, "sess", REALISTIC_READS)

    captured = store.get_entries("sess")
    assert [e.id for e in captured] == [e.id for e in read]
    assert [e.target for e in captured] == [p for p, _, _ in REALISTIC_READS]


# ---------------- 3. correct labeling per file ----------------

def test_cloned_repo_readme_is_untrusted(store, lab):
    e = read_file(store, lab, "sess", "/work/README.md", "cloned-repo")
    assert e.labels.trust == Trust.UNTRUSTED
    assert e.labels.sensitivity == Sensitivity.PUBLIC


def test_env_file_is_secret(store, lab):
    e = read_file(store, lab, "sess", "/work/.env", "user", kind=Kind.SECRET)
    assert e.labels.sensitivity == Sensitivity.SECRET


def test_user_source_file_is_trusted_public(store, lab):
    e = read_file(store, lab, "sess", "/work/src/app.py", "user")
    assert e.labels.trust == Trust.TRUSTED
    assert e.labels.sensitivity == Sensitivity.PUBLIC


def test_bait_file_flagged(store, lab):
    e = read_file(store, lab, "sess", "/work/aws_prod_credentials.txt",
                  "workspace")
    assert e.labels.bait is True


# ---------------- 4. field fidelity ----------------

def test_captured_fields_match_the_read(store, lab):
    e = read_file(store, lab, "sess", "/work/.aws/credentials", "operator",
                  kind=Kind.SECRET, op=Op.READ_FILE)

    captured = store.get_entries("sess")[0]
    assert captured.target == "/work/.aws/credentials"
    assert captured.origin == "operator"
    assert captured.op == Op.READ_FILE
    assert captured.kind == Kind.SECRET
    # The captured object is the same record that was appended (no copy/mutate).
    assert captured is e


# ---------------- 5. no eviction / no loss at scale ----------------

def test_no_eviction_at_scale(store, lab):
    n = 250
    for i in range(n):
        read_file(store, lab, "sess", f"/work/file_{i}.py", "user")

    captured = store.get_entries("sess")
    assert len(captured) == n
    assert [e.target for e in captured] == [f"/work/file_{i}.py" for i in range(n)]


# ---------------- 6. session isolation ----------------

def test_reads_do_not_cross_sessions(store, lab):
    read_file(store, lab, "A", "/work/README.md", "cloned-repo")
    read_file(store, lab, "A", "/work/.env", "user", kind=Kind.SECRET)
    read_file(store, lab, "B", "/work/src/app.py", "user")

    a_targets = [e.target for e in store.get_entries("A")]
    b_targets = [e.target for e in store.get_entries("B")]
    assert a_targets == ["/work/README.md", "/work/.env"]
    assert b_targets == ["/work/src/app.py"]
    assert "/work/.env" not in b_targets


# ---------------- 7. duplicate reads ----------------

def test_duplicate_reads_produce_two_entries(store, lab):
    # Documented behavior: the store captures *events*, not a set of files.
    # Reading the same file twice is two distinct reads and must be recorded
    # as two entries (otherwise the audit trail would lose a real access).
    first = read_file(store, lab, "sess", "/work/.env", "user", kind=Kind.SECRET)
    second = read_file(store, lab, "sess", "/work/.env", "user", kind=Kind.SECRET)

    captured = store.get_entries("sess")
    assert len(captured) == 2
    assert first.id != second.id
    assert [e.target for e in captured] == ["/work/.env", "/work/.env"]


# ---------------- 8. reads reflected in aggregation ----------------

def test_aggregate_reflects_untrusted_and_secret_reads(store, lab):
    untrusted = read_file(store, lab, "sess", "/work/README.md", "cloned-repo")
    secret = read_file(store, lab, "sess", "/work/.env", "user",
                       kind=Kind.SECRET)
    # A later sink action the guard would evaluate.
    action = ContextEntry(
        id=f"sess:{next(_ids)}", ts=time.time(), session_id="sess",
        kind=Kind.ACTION, channel=Channel.EGRESS, op=Op.NETWORK_REQUEST,
        target="evil.example", origin="workspace",
        labels=lab.label("evil.example", "user"),
    )
    store.append(action)

    agg = store.aggregate("sess", action)

    assert agg.reached_untrusted is True
    assert agg.reached_secret is True
    # supporting_entry_ids point back to the exact read entries that tainted.
    assert set(agg.supporting_entry_ids) == {untrusted.id, secret.id}
