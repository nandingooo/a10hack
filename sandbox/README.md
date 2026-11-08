# Sandbox and gateway

Each agent session runs in its own locked-down Docker container. The only thing a container can reach is the **gateway**. Every file read, web request, outbound send, privileged action and model call goes through the gateway, which tags what the agent has seen and decides what it may do.

Read [gateway/README.md](../gateway/README.md) for the rules, the gateway tools, and the contracts for storage, dashboard and risk.

## How it fits together

```
 host                                    sandbox (one per session)
 ─────────────────────────────           ──────────────────────────────────────
 sandbox API :9000  ◄── create/          agent (e.g. Claude Code via a10-agent)
   (sandbox/api.py)      destroy           │  ANTHROPIC_BASE_URL = http://gateway:8080/llm
        ▲                                  │  ANTHROPIC_AUTH_TOKEN = session token
        │ resolve token                    │  MCP tools at http://gateway:8080/mcp
        │                                  ▼
 gateway container  ◄──── session network (internal, no internet, no host access)
   a10-gateway :8080
        │  checks + tags + rules
        ▼
 model provider (API key added here) · public web (vetted IPs only)
```

- **Session network:** one internal Docker network per session. It has no route to the internet, to the Docker host, or to other sessions. The gateway is attached to every session network under the name `gateway`.
- **No project files inside:** nothing is mounted. Agents get files through the gateway's `read_file` tool, so every read is seen and tagged.
- **No API key inside:** the sandbox has only a session token. The gateway swaps it for the real key on model calls.

## What the sandbox enforces

| Control | Setting |
|---|---|
| Network | internal-only network; the host gets no IP on it (`inhibit_ipv4`); IPv6 disabled |
| Filesystem | read-only root; scratch space only in small in-memory folders (`/tmp`, `/home/agent/work`), which can't run programs |
| Privileges | non-root (uid 10001), all capabilities dropped, `no-new-privileges` |
| System calls | Docker's default seccomp profile, applied explicitly ([seccomp-default.json](seccomp-default.json)), because some Docker installs default to none |
| Resources | memory, CPU, process and scratch limits, sized by agent count (below) |
| Logs | container stdout capped at 5 MB on the host |
| Lifetime | removed after `SANDBOX_MAX_AGE` (default 2 h), after `SANDBOX_IDLE_TIMEOUT` with no gateway activity (default 30 min), or when the container exits |

## Set up locally

Needs Docker Desktop (running) and Python 3.10+.

```sh
git clone -b owen/sandbox https://github.com/nandingooo/a10hack.git
cd a10hack
python3 -m venv .venv
source .venv/bin/activate
pip install -r sandbox/requirements-dev.txt
docker build -t a10-agent-sandbox sandbox/
docker build -f sandbox/Dockerfile.claude -t a10-agent-claude sandbox/
```

`a10-agent-claude` has Claude Code installed and is only needed to run a real agent.

## Run the whole stack

Terminal 1, the sandbox API:

```sh
export SANDBOX_API_KEY=devkey
uvicorn api:app --app-dir sandbox --port 9000
```

Terminal 2, the gateway and a demo:

```sh
export SANDBOX_API_KEY=devkey GATEWAY_ADMIN_KEY=devadmin
./gateway/run.sh
python gateway/demo.py
```

`demo.py` runs six scripted scenarios in real sandboxes (normal work, prompt-injection leak, secret to an unapproved destination, decoy read, untrusted page then a risky action, untagged file then credentials) and prints each decision.

### With a real agent (Claude Code)

To use the real model API, start the gateway with your key:

```sh
ANTHROPIC_API_KEY=sk-ant-... ./gateway/run.sh
```

To test without a key, use the mock model:

```sh
./gateway/mock_upstream.sh
LLM_UPSTREAM=http://a10-mock-llm:8090 ANTHROPIC_API_KEY=mock-key UPSTREAM_NETWORK=a10-upstream ./gateway/run.sh
```

Then create a session from the Claude Code image and run the agent inside it:

```sh
SANDBOX_IMAGE=a10-agent-claude:latest python sandbox/manager.py create demo --agents 2
docker exec a10-sbx-demo a10-agent -p "List the project files"
python sandbox/manager.py destroy demo
```

The mock model understands scripted tool calls. A prompt with lines like `CALL read_file {"path": "docs/readme.md"}` makes it call those gateway tools in order, then reply with the results.

## Sandbox API

All endpoints except `/healthz` need `Authorization: Bearer $SANDBOX_API_KEY`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/sessions` | Create a sandbox. Body: `{"session_id"?, "env"?, "agents"?}`. Returns the session token; this is the only time it's shown. |
| GET | `/sessions` | List sandboxes |
| GET | `/sessions/{id}` | One sandbox's status |
| DELETE | `/sessions/{id}` | Destroy it |
| POST | `/sessions/resolve` | `{"token"}` → `{"session_id"}`; the gateway uses this to identify callers |
| POST | `/sessions/{id}/touch` | Record activity (resolve does this too) |
| POST | `/reap` | Run cleanup now |

The same operations from the command line: `python sandbox/manager.py create|list|destroy|reap`.

### Sizing for several agents in one sandbox

`agents: N` gives the sandbox:

- memory: 128 MB plus a per-agent amount
- processes: 64 plus 32 per agent
- CPU: half a CPU per agent, between 1 and 4
- scratch space: 64 MB plus 8 MB per agent

The default cap is 32 agents. The per-agent memory comes from the image's `a10.per_agent_mem_mb` label (160 MB for Claude Code), otherwise 48 MB. `SANDBOX_PER_AGENT_MEM_MB` overrides both. Without `agents`, a sandbox gets fixed limits: 512 MB, 1 CPU, 256 processes.

Agents in the same sandbox share its limits and its scratch files, so put only one session's agents together.

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_API_KEY` | random, printed at startup | key for the sandbox API |
| `SANDBOX_IMAGE` | `a10-agent-sandbox:latest` | image every sandbox runs |
| `GATEWAY_CONTAINER` / `GATEWAY_PORT` | `a10-gateway` / `8080` | gateway to attach |
| `SANDBOX_MEM` / `SANDBOX_CPUS` / `SANDBOX_PIDS` / `SANDBOX_TMPFS` | `512m` / `1.0` / `256` / `64m` | limits when `agents` isn't given |
| `SANDBOX_BASE_MEM_MB` / `SANDBOX_PER_AGENT_MEM_MB` | `128` / image label or `48` | sizing when `agents` is given |
| `SANDBOX_MAX_AGENTS` / `SANDBOX_MAX_CPUS` | `32` / `4` | sizing caps |
| `SANDBOX_MAX_AGE` / `SANDBOX_IDLE_TIMEOUT` | `7200` / `1800` s | cleanup limits |
| `SANDBOX_REAP_INTERVAL` | `60` s (`0` = off) | how often cleanup runs |

## Tests

| Command | What it checks | Needs |
|---|---|---|
| `pytest sandbox gateway` | API, cleanup, rules, model proxy, MCP, address checks (60 tests) | Docker, for the cleanup tests |
| `python sandbox/smoke_test.py` | basic isolation of one sandbox (10 checks) | Docker |
| `python sandbox/swarm_test.py --agents 5 --per-sandbox 2` | hostile agents try to escape in parallel (68 kinds of attempt). With the real gateway running, it also tries reaching internal targets through it. | Docker; full stack for the gateway checks |
| `python sandbox/capacity_test.py --agents 20` | N agents fit in one sandbox without being killed | Docker |
| `python gateway/bench_llm.py` | model-call latency, direct vs. through the gateway | stack with the mock model |

Last results:
- swarm: 68/68 held, for both images
- 16 Claude Code agents in one sandbox: 16/16 completed
- the gateway added 4 ms to the first token with one call at a time, and 40 ms with 32 calls starting at the same instant

## Troubleshooting

- **`Error while fetching server API version`:** Docker Desktop isn't running.
- **`gateway container 'a10-gateway' not running`:** start the gateway before creating sessions. Sandboxes created earlier aren't attached to it.
- **`409 already exists`:** delete the old session, or run `python sandbox/manager.py destroy <id>`.
- **Remove everything by hand:**
  ```sh
  docker rm -f $(docker ps -aq --filter label=a10.session_id)
  docker network prune
  ```
