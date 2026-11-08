# AgentAirlock Guard

The guard is a long-running FastAPI service. It waits for a trusted hook or proxy to submit an event. `POST /decide` checks the session status, loads evidence from SQLite, applies the policy, and records the verdict in one transaction. `POST /results` adds observed outcomes to the same audit log. A request to read a file establishes exposure only once a trusted sensor records that the data was made available to the agent.

SQLite is owned by the guard. The default database is `gateway/data/airlock.sqlite3` when started from `gateway/`. It keeps session status, verdicts, and outcome metadata across restarts. Mount the DB directory on persistent storage when running the guard in a container. Raw tool output, outbound request bodies, and plaintext sensor tokens are excluded from the audit log.

## Run locally

From the repository root, using Python 3.11 or later:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r gateway/requirements.txt
export AIRLOCK_OPERATOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
cd gateway
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8080
```

`AIRLOCK_DB` overrides the DB path. The workspace defaults to `/home/agent/work`, matching `sandbox/manager.py`. `AIRLOCK_WORKSPACE_ROOT` overrides that path. Use the same workspace for the guard and sensor.

## Request flow

| Endpoint | Caller | Purpose |
|---|---|---|
| `GET /healthz` | Local health check | Verify the guard can access its DB. |
| `POST /sessions` | Operator backend | Register a session. Pass `{"session_id":"demo"}` to use the same ID as the sandbox API. The guard returns a `sensor_token` once. |
| `POST /decide` | Trusted sensor | Submit a pending action. The response contains `decision_id`, `decision`, `rule`, `reason`, and `evidence_ids`. |
| `POST /results` | Trusted sensor | Report the outcome of an allowed action. Only a file read that releases data contributes exposure evidence. An identical retry returns the same result ID. |
| `GET /sessions/{id}/history?after=0&limit=100` | Operator backend | Read ordered audit events for one session. Use the last event ID as `after` to fetch new events. |
| `POST /sessions/{id}/stop` | Operator backend | Close the guard session and request sandbox termination when configured. |

The operator backend authenticates with `Authorization: Bearer $AIRLOCK_OPERATOR_TOKEN`. A trusted sensor uses its session-specific guard token in the same header. Keep the operator token in the backend and the guard's sensor token in the trusted hook or proxy. The sandbox manager's `SESSION_TOKEN` is available inside the agent container and serves a separate purpose.

Example request from a trusted sensor before reading a fixture:

```json
{"session_id":"demo","channel":"hook","op":"ReadFile","target":"/home/agent/work/.env","origin":"workspace"}
```

Example result once the read succeeds, before releasing its data to the agent:

```json
{"session_id":"demo","decision_id":1,"outcome":"succeeded","released_data":true}
```

Use the actual `decision_id` from the guard. If the result cannot be recorded, withhold the data. For a failed read with no data, report `outcome: "failed"` and `released_data: false`. For outbound actions, forward only after an explicit `allow` for that request. A timeout, error, malformed response, `block`, or `stop` leaves the action blocked.

## Policy coverage in this slice

- Supports normalized file reads, writes, and deletes within the managed workspace. The root and `.git` are protected against modification. The trusted sensor is responsible for resolving the actual target in the sandbox and enforcing the verdict on that same target.
- Supports a hostname allowlist and one demo MCP external write, `post_support_update`. The trusted proxy should bind that name to the approved support endpoint. Prior secret exposure blocks this call and supplies the result ID. A generic allowlisted hostname still follows the hostname rule.
- A canary file target or an exact bait token in the outbound body supplied for inspection closes the run. The guard blocks operations outside the current policy coverage, including generic shell and model calls.
- Sandbox termination uses the team's existing `DELETE /sessions/{id}` API. Set `AIRLOCK_SANDBOX_URL` and `SANDBOX_API_KEY` on the guard to enable it. The guard commits `KILLED` before calling the sandbox. If termination returns `pending`, the operator can retry the stop endpoint.

This service receives events and returns verdicts. The CLI hook, MCP forwarding, and egress proxy still need to send those events and enforce the response on the actual action path.

## Test

From the repository root:

```sh
python -m unittest -v gateway.test_guard
```
