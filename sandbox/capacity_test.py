"""Can one sandbox hold N agents at once? Run N normal agents in a sandbox sized for N.

Run: python sandbox/capacity_test.py --agents 20 [--work-mib 20] [--unsized]
Exit code 0 = every agent finished without being killed.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))
from manager import SandboxManager  # noqa: E402

# A stand-in for a real agent: interpreter + HTTP client + some working memory, mostly idle.
AGENT = (
    "import requests, time\n"
    "b = bytearray({work} * 2**20); b[::4096] = b'x' * len(b[::4096])\n"
    "time.sleep({hold})\n"
    "print('done')"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", type=int, default=10)
    ap.add_argument("--work-mib", type=int, default=20, help="working memory per agent")
    ap.add_argument("--hold", type=int, default=12, help="seconds each agent stays alive")
    ap.add_argument("--unsized", action="store_true", help="use the fixed default limits instead")
    args = ap.parse_args()

    mgr = SandboxManager()
    sid = f"cap-{uuid.uuid4().hex[:6]}"
    info = mgr.create(sid, agents=None if args.unsized else args.agents)
    container = mgr.client.containers.get(info.container_name)
    limits = info.limits
    print(f"sandbox limits: memory {limits['mem_limit']}, cpus {limits['cpus']}, "
          f"processes {limits['pids_limit']}; starting {args.agents} agents...")

    code = AGENT.format(work=args.work_mib, hold=args.hold)
    exit_codes: list[int] = []
    lock = threading.Lock()

    def run():
        rc, _ = mgr.exec(sid, ["python3", "-c", code])
        with lock:
            exit_codes.append(rc)

    peak = 0.0
    try:
        threads = [threading.Thread(target=run) for _ in range(args.agents)]
        for t in threads:
            t.start()
        while any(t.is_alive() for t in threads):
            stats = container.stats(stream=False)["memory_stats"]
            peak = max(peak, stats.get("usage", 0) / 2**20)
            time.sleep(1)
    finally:
        mgr.destroy(sid)

    killed = sum(1 for rc in exit_codes if rc != 0)
    print(f"{args.agents} agents: {args.agents - killed} finished, {killed} killed; "
          f"peak memory {peak:.0f} MiB (~{peak / args.agents:.0f} MiB per agent)")
    return 1 if killed else 0


if __name__ == "__main__":
    sys.exit(main())
