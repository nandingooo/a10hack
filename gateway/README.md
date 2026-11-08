# Gateway (placeholder)

Everything an agent does outside its sandbox goes through here. The gateway tags what the agent has read, applies the rules, and logs every decision. It's a working placeholder: the interfaces below are what the dashboard, storage and risk layer can build against now. The in-memory parts are meant to be replaced.

Setup and the overall architecture are in [sandbox/README.md](../sandbox/README.md).

## What agents can call

Sandboxes authenticate with `Authorization: Bearer $SESSION_TOKEN`. The gateway checks the token with the sandbox API.

| Endpoint | Purpose |
|---|---|
| `GET /tools/list_files` | list workspace files |
| `POST /tools/read_file {"path"}` | read a file; its tags are applied to the session |
| `POST /tools/fetch_url {"url"}` | fetch a web page; the session becomes untrusted |
| `POST /tools/send {"url", "body"}` | send data out |
| `POST /tools/action {"kind", "target"}` | privileged action (`delete`, `credentials`, `permissions`, ...); a placeholder that performs nothing |
| `POST /mcp` | the same five tools as an MCP server (`mcp__gateway__*` in Claude Code) |
| `POST /llm/v1/messages` (and `/count_tokens`) | model calls; the API key is added here and replies stream through |

A blocked call returns `403` with `{"decision", "rule", "reason"}`. Through MCP, it comes back as a tool error, so the agent sees the reason and carries on.

## Tags

- **Trust:** trusted > unknown > untrusted.
- **Sensitivity:** public < sensitive < secret.
- **Bait:** a yes/no flag for decoys.

File tags live in [workspace/tags.json](workspace/tags.json):
- Untagged files count as unknown trust and sensitive.
- Fetched web pages count as untrusted and public.

A session keeps the **lowest trust and highest sensitivity** of everything it has read. Its tags never relax.

## Rules

The strictest decision wins: block > ask > allow. "Ask" is currently returned as a denial, because the approval flow isn't built yet.

| Rule | When | Decision |
|---|---|---|
| R0 | `fetch_url` or `send` to anything that isn't a public internet address over http(s) on 80/443: loopback, private networks, cloud metadata, the Docker host, internal names, names that resolve to those | block + alert |
| R1 | risky action (`delete`, `credentials`, `permissions`) after untrusted content | block |
| R1 | the same after unknown content | ask |
| R2 | session sensitivity above what the destination is approved for (`APPROVED_DESTINATIONS`; unlisted hosts = public) | secret: block, sensitive: ask |
| R3 | untrusted + sensitive in context + sending out | block + alert |
| R4 | a decoy was read | block everything that leaves, model calls included + alert |
| model calls | the destination is fixed to the provider, so R2/R3 don't apply; only R4 does. Tools that would run on the provider's servers (web search, web fetch, code execution) and remote MCP servers are removed from requests. | allow |

Outbound requests (`OFFLINE=0`) connect to the exact IP address R0 checked, so a DNS answer that changes on a second lookup can't reach internal addresses. Redirects aren't followed, and response bodies are capped at 256 KiB.

## Contracts

### Josh: storage

The gateway keeps three in-memory stores in [app.py](app.py): `sessions`, `events` and `alerts`. Replace them with the database. They hold metadata only, never file contents or model messages.

- **Session:** `{session_id, trust, sensitivity, bait, reads[]}`, where each entry of `reads` is `{source, trust, sensitivity, bait}`.
- **Event:** one per read, action or model call:
  ```
  {ts, session_id, kind, ...detail, session_tags, decision?, rule?, reason?}
  ```
  - `kind`: `list_files | read_file | fetch_url | send | action | llm_call`
  - `detail`, by kind:
    - `read_file`: `path`, `file_tags`
    - `fetch_url`: `url`, `destination`, `ip`
    - `send`: `url`, `destination`, `bytes`
    - `action`: `action`, `target`
    - `llm_call`: `model`, `messages` (count), `stream`, `removed`, `status`, `upstream_first_byte_ms`, `duration_ms`
- **Alert:** an event whose decision raised an alert (R0, R3, R4).

Moving these to shared storage also lets the gateway run several processes. That removes the extra delay with many simultaneous model calls.

### Nandin: dashboard

Read-only admin API with `Authorization: Bearer $GATEWAY_ADMIN_KEY`. It's only accepted from the host side, never from a sandbox.

| Endpoint | Returns |
|---|---|
| `GET /admin/sessions` | `[{session_id, trust, sensitivity, bait, reads, events}]` |
| `GET /admin/sessions/{id}/events` | the session's events, oldest first |
| `GET /admin/alerts` | all alert events |

`run.sh` publishes the gateway only at `127.0.0.1:8080`. A static site on S3 can't call that directly, so put a small backend in front, or expose the gateway behind auth.

**Still needed: an approval flow.** "Ask" decisions should become pending requests the dashboard can approve or deny, denied after a timeout.

### William: risk layer

Set `RISK_URL`. The gateway POSTs this before each `fetch_url`, `send` and `action`:

```json
{"session_id": "...", "action": "send", "args": {"url": "...", "bytes": 42},
 "session_tags": {"trust": "untrusted", "sensitivity": "sensitive", "bait": false},
 "recent_events": [ ...last 20 events... ]}
```

It expects `{"decision": "allow" | "ask" | "block", "reason": "..."}` back:
- The risk layer can only make a decision **stricter**. If its answer is more lenient than the rules', the rules' decision stands.
- If it takes longer than 0.5 s or errors, the rules' decision stands.
- Model calls aren't sent to it, to keep their latency low.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_API_URL` / `SANDBOX_API_KEY` | `http://host.docker.internal:9000` / — | how the gateway resolves session tokens |
| `GATEWAY_ADMIN_KEY` | `devadmin` in `run.sh` | admin API key |
| `ADMIN_SOURCES` | `auto` (host side only) | where admin calls are accepted from; `any` is for tests only |
| `FILES_DIR` / `TAGS_FILE` | `/data/files` / `/data/tags.json` | workspace and its tags (mounted read-only by `run.sh` from `gateway/workspace`) |
| `APPROVED_DESTINATIONS` | `{"api.internal.example": "sensitive"}` in `run.sh` | highest sensitivity each host may receive |
| `OFFLINE` | `1` | `1` simulates `fetch_url` and `send`; `0` sends for real, pinned to the checked IP |
| `ANTHROPIC_API_KEY` / `LLM_UPSTREAM` | — / `https://api.anthropic.com` | model provider; `/llm` returns 503 without a key |
| `RISK_URL` | unset | risk layer endpoint |
| `UPSTREAM_NETWORK` | unset | extra Docker network for `run.sh` to join (the mock model) |

## Files

| File | Contents |
|---|---|
| [policy.py](policy.py) | tags, session state, rules R1–R4, model-call rule (no I/O) |
| [egress.py](egress.py) | R0 address checks and pinned outbound requests |
| [app.py](app.py) | tools, identity, logging, risk hook, admin API |
| [llm.py](llm.py) | streaming model proxy |
| [mcp.py](mcp.py) | MCP server for the tools |
| [mock_llm.py](mock_llm.py), [mock_upstream.sh](mock_upstream.sh) | stand-in model API for tests and benchmarks |
| [demo.py](demo.py), [bench_llm.py](bench_llm.py) | end-to-end scenarios and the latency benchmark |
