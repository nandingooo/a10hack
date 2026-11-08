"""Checks the isolation guarantees against a real Docker daemon.

Run: python sandbox/smoke_test.py
"""

import sys
import uuid

sys.path.insert(0, __import__("os").path.dirname(__file__))
from manager import SandboxManager  # noqa: E402

PY = "python3", "-c"

CHECKS = [
    ("no internet", [*PY, "import socket; socket.create_connection(('1.1.1.1', 80), timeout=3)"], False),
    ("no DNS to outside", [*PY, "import socket; socket.gethostbyname('example.com')"], False),
    ("root fs read-only", [*PY, "open('/etc/x', 'w')"], False),
    ("runs as non-root", [*PY, "import os; assert os.getuid() == 10001"], True),
    ("scratch dir writable", [*PY, "open('/home/agent/work/f', 'w').write('ok')"], True),
    ("tmp is noexec", ["sh", "-c", "cp /bin/true /tmp/t && /tmp/t"], False),
]


def main() -> int:
    mgr = SandboxManager()
    a, b = f"smoke-{uuid.uuid4().hex[:8]}", f"smoke-{uuid.uuid4().hex[:8]}"
    failed = 0
    try:
        info_a = mgr.create(a)
        info_b = mgr.create(b)
        checks = CHECKS + [
            ("sessions can't see each other",
             [*PY, f"import socket; socket.create_connection(('{info_b.container_name}', 80), timeout=3)"],
             False),
        ]
        checks += [
            ("syscall filter (seccomp) on", [*PY, "assert 'Seccomp:\\t2' in open('/proc/self/status').read()"], True),
            ("no IPv6 addresses", [*PY, "assert all(l.split()[-1] == 'lo' for l in open('/proc/net/if_inet6'))"
                                   " if __import__('os').path.exists('/proc/net/if_inet6') else None"], True),
        ]
        log_cfg = mgr.client.containers.get(info_a.container_name).attrs["HostConfig"]["LogConfig"]
        ok = log_cfg.get("Config", {}).get("max-size") == "5m"
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  container logs capped on host  {log_cfg}" if not ok else
              "PASS  container logs capped on host")
        for name, cmd, should_succeed in checks:
            code, out = mgr.exec(a, cmd)
            ok = (code == 0) == should_succeed
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n      exit={code} {out.strip()[-200:]}"))
    finally:
        mgr.destroy(a)
        mgr.destroy(b)
    print(f"\n{len(checks) + 1 - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
