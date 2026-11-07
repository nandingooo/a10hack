"""Reaper tests against a real Docker daemon (skipped if Docker or the image is missing)."""

import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402

docker = pytest.importorskip("docker")

from manager import SandboxManager  # noqa: E402


@pytest.fixture
def mgr():
    try:
        m = SandboxManager()
        m.client.images.get(m.config.image)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"Docker or sandbox image unavailable: {e}")
    created = []
    m.new = lambda: (created.append(sid := f"reap-{uuid.uuid4().hex[:8]}"), m.create(sid))[1]
    yield m
    for sid in created:
        m.destroy(sid)


def ids(reaped):
    return {r["session_id"] for r in reaped}


def test_max_age(mgr):
    info = mgr.new()
    assert info.session_id not in ids(mgr.reap(max_age=3600))
    assert info.session_id in ids(mgr.reap(max_age=3600, now=time.time() + 3601))
    assert mgr.get(info.session_id) is None


def test_idle_resets_on_activity(mgr):
    info = mgr.new()
    later = time.time() + 100
    mgr.last_seen[info.session_id] = later - 50
    assert info.session_id not in ids(mgr.reap(idle_timeout=60, now=later))
    mgr.last_seen[info.session_id] = later - 61
    assert info.session_id in ids(mgr.reap(idle_timeout=60, now=later))


def test_exited_and_orphaned_network(mgr):
    a, b = mgr.new(), mgr.new()
    mgr.client.containers.get(a.container_name).stop(timeout=1)
    mgr.client.containers.get(b.container_name).remove(force=True)  # leaves its network behind
    reaped = {r["session_id"]: r["reason"] for r in mgr.reap()}
    assert reaped[a.session_id] == "container exited"
    assert reaped[b.session_id] == "orphaned network"
    assert not mgr.client.networks.list(names=[a.network, b.network])
