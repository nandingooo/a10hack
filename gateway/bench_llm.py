"""Latency of model calls: direct to the upstream vs. from a sandbox through the gateway.

Needs the stack from gateway/mock_upstream.sh + gateway/run.sh (+ sandbox API on :9000).
Run: python gateway/bench_llm.py [--concurrency 1 32] [--rounds 5]

Both paths hit the same mock model, so the difference is what the gateway adds.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sandbox"))
import docker  # noqa: E402

from manager import SandboxConfig, SandboxManager  # noqa: E402

# Runs inside a container. Streams N concurrent requests, reports per-request timings.
CLIENT = r'''
import http.client, json, sys, threading, time, urllib.parse
url, auth_header, auth_value, n, rounds = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
u = urllib.parse.urlparse(url)
body = json.dumps({"model": "bench", "max_tokens": 64, "stream": True,
                   "messages": [{"role": "user", "content": "hello"}]})
out = []
def one():
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
    t0 = time.perf_counter()
    c.request("POST", u.path, body, {auth_header: auth_value, "content-type": "application/json",
                                     "anthropic-version": "2023-06-01"})
    r = c.getresponse()
    r.read1(1); ttft = time.perf_counter() - t0
    while r.read1(65536): pass
    out.append({"status": r.status, "ttft": ttft, "total": time.perf_counter() - t0})
    c.close()
for _ in range(rounds):
    ts = [threading.Thread(target=one) for _ in range(n)]
    [t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps(out))
'''


def summarize(rows):
    ok = [r for r in rows if r["status"] == 200]
    if not ok:
        return {"ok": 0}
    ttft = sorted(r["ttft"] * 1000 for r in ok)
    total = sorted(r["total"] * 1000 for r in ok)
    p95 = lambda xs: xs[min(len(xs) - 1, int(len(xs) * 0.95))]  # noqa: E731
    return {"ok": len(ok), "errors": len(rows) - len(ok),
            "ttft_med": statistics.median(ttft), "ttft_p95": p95(ttft),
            "total_med": statistics.median(total), "total_p95": p95(total)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 32])
    ap.add_argument("--rounds", type=int, default=5)
    args = ap.parse_args()

    client = docker.from_env()
    mgr = SandboxManager(SandboxConfig())
    sid = f"bench-{uuid.uuid4().hex[:6]}"
    info = mgr.create(sid, agents=32)
    results = []
    try:
        for n in args.concurrency:
            direct = client.containers.run(
                "a10-agent-sandbox:latest", ["python3", "-c", CLIENT, "http://a10-mock-llm:8090/v1/messages",
                                             "x-api-key", "mock-key", str(n), str(args.rounds)],
                network="a10-upstream", remove=True)
            via = mgr.exec(sid, ["python3", "-c", CLIENT, f"{info.gateway_url}/llm/v1/messages",
                                 "Authorization", f"Bearer {info.session_token}", str(n), str(args.rounds)])[1]
            results.append((n, summarize(json.loads(direct)), summarize(json.loads(via))))
    finally:
        mgr.destroy(sid)

    print(f"\n{'concurrent':>10} | {'path':<16} | {'ok':>4} | {'first token med / p95':>22} | {'full reply med / p95':>21}")
    print("-" * 86)
    for n, d, g in results:
        for name, s in (("direct", d), ("via gateway", g)):
            print(f"{n:>10} | {name:<16} | {s['ok']:>4} | {s['ttft_med']:>9.1f} / {s['ttft_p95']:>6.1f} ms "
                  f"| {s['total_med']:>8.1f} / {s['total_p95']:>6.1f} ms")
        print(f"{'':>10} | {'gateway adds':<16} | {'':>4} | {g['ttft_med'] - d['ttft_med']:>+9.1f} ms{'':>11}"
              f"| {g['total_med'] - d['total_med']:>+8.1f} ms")
        print("-" * 86)
    return 0


if __name__ == "__main__":
    sys.exit(main())
