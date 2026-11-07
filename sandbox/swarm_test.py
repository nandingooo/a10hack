"""Start N sandboxes at once, run the hostile escape agent in each, report any escape.

Run: python sandbox/swarm_test.py --agents 5
Exit code 0 = every escape attempt in every sandbox was blocked.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
from docker.errors import NotFound  # noqa: E402

from manager import SandboxManager  # noqa: E402

AGENT_CODE = open(os.path.join(os.path.dirname(__file__), "escape_agent.py")).read()
STANDIN_GATEWAY_IMAGE = "python:3.12-slim"


def ensure_gateway(mgr: SandboxManager) -> bool:
    """Start a stand-in gateway if none is running. Returns True if we started it."""
    try:
        mgr.client.containers.get(mgr.config.gateway_container)
        return False
    except NotFound:
        mgr.client.containers.run(
            STANDIN_GATEWAY_IMAGE, ["python", "-m", "http.server", str(mgr.config.gateway_port)],
            name=mgr.config.gateway_container, detach=True, remove=True,
        )
        return True


def gateway_ip_of(client, network_name: str) -> list[str]:
    cfg = client.networks.get(network_name).attrs.get("IPAM", {}).get("Config") or []
    return [c["Gateway"] for c in cfg if c.get("Gateway")]


def run_agent(mgr: SandboxManager, info, cfg: dict) -> list[dict]:
    container = mgr.client.containers.get(info.container_name)
    res = container.exec_run(["python3", "-c", AGENT_CODE, json.dumps(cfg)], user="10001:10001", demux=True)
    stdout = (res.output[0] or b"").decode(errors="replace").strip()
    try:
        return json.loads(stdout.splitlines()[-1])["results"]
    except (IndexError, ValueError, KeyError):
        stderr = (res.output[1] or b"").decode(errors="replace")
        return [{"check": "agent crashed", "expect": "allowed", "outcome": "blocked", "ok": False,
                 "detail": f"exit {res.exit_code}: {stderr[-300:]}"}]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", type=int, default=5)
    ap.add_argument("--per-sandbox", type=int, default=1, help="agents run in parallel inside each sandbox")
    ap.add_argument("--no-gateway", action="store_true", help="don't start a stand-in gateway")
    ap.add_argument("--verbose", action="store_true", help="show every check, not just failures")
    args = ap.parse_args()

    mgr = SandboxManager()
    started_gateway = False if args.no_gateway else ensure_gateway(mgr)
    run_id = uuid.uuid4().hex[:6]
    sessions = []
    try:
        with ThreadPoolExecutor(args.agents) as pool:
            sessions = list(pool.map(lambda i: mgr.create(f"swarm-{run_id}-{i}"), range(args.agents)))
        print(f"started {len(sessions)} sandboxes; running {args.per_sandbox} escape agent(s) "
              f"in parallel in each...\n")

        endpoints = []
        for info in sessions:
            attrs = mgr.client.containers.get(info.container_name).attrs
            endpoints.append({"name": info.container_name,
                              "ip": attrs["NetworkSettings"]["Networks"][info.network]["IPAddress"]})
        bridge_gw = gateway_ip_of(mgr.client, "bridge")

        def cfg_for(i, info):
            return {
                "gateway": None if args.no_gateway else f"gateway:{mgr.config.gateway_port}",
                "peers": [e for j, e in enumerate(endpoints) if j != i],
                "host_ips": sorted(set(bridge_gw + gateway_ip_of(mgr.client, info.network))),
            }

        jobs = [(i, info) for i, info in enumerate(sessions) for _ in range(args.per_sandbox)]
        with ThreadPoolExecutor(len(jobs)) as pool:
            all_results = list(pool.map(lambda p: run_agent(mgr, p[1], cfg_for(*p)), jobs))
    finally:
        for info in sessions:
            mgr.destroy(info.session_id)
        if started_gateway:
            try:
                mgr.client.containers.get(mgr.config.gateway_container).remove(force=True)
            except NotFound:
                pass

    # Group by check (peer checks name a specific peer; fold them into one row).
    rows = defaultdict(lambda: {"ok": 0, "fail": [], "expect": ""})
    for agent_i, results in enumerate(all_results):
        for r in results:
            key = r["check"]
            if key.startswith("peer "):
                key = "peer " + key.split(" ", 2)[1].split("-")[0] + " " + key.rsplit(":", 1)[-1] \
                    if ":" in key else "peer resolve name"
                key = key.replace("peer resolve name", "peer: resolve other sandbox by name")
                if key.startswith("peer a10"):
                    key = "peer: tcp to other sandbox port " + key.rsplit(" ", 1)[-1]
            row = rows[key]
            row["expect"] = r["expect"]
            if r["ok"]:
                row["ok"] += 1
            else:
                sbx, k = divmod(agent_i, args.per_sandbox)
                row["fail"].append(f"sandbox {sbx} agent {k}: {r['outcome']} — {r['detail']}")

    failures = 0
    for check, row in sorted(rows.items(), key=lambda kv: (not kv[1]["fail"], kv[0])):
        bad = bool(row["fail"])
        failures += bad
        if bad or args.verbose:
            status = "FAIL" if bad else "PASS"
            print(f"{status}  {check}  (expect {row['expect']}; ok in {row['ok']} attempts)")
            for f in row["fail"][:3]:
                print(f"        {f}")
    total = len(rows)
    print(f"\n{args.agents} sandboxes x {args.per_sandbox} agents = {len(all_results)} agents, {total} kinds of attempt: {total - failures} held, {failures} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
