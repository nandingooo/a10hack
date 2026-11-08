# Confirmed provenance and outbound-write policy

The guard now distinguishes permission to contact a host from permission to send
data after consuming secret context. The same POST to github.com is allowed in
a clean session and blocked as `secret_upload` after a successfully recorded
secret read. An approved GET remains allowed. This is conservative containment,
not a claim that the outbound bytes were inspected or proved secret.

Run the reproducible policy demonstration from the workspace root:

```powershell
python trust_agent/experiments/provenance_demo.py
python -m pytest trust_agent/tests -q
```

The demonstration feeds synthetic events to the real decision engine; it makes
no network calls and does not run a language model. The tests additionally run
the actual hook subprocess against a local HTTP guard and check its deny output.

## Install the upgraded sensor

Install all three events into the project where the agent will run, then start
a fresh Claude session after restarting the guard:

```powershell
python trust_agent/sandbox/install_hooks.py C:\Users\jackd\trustagent-demo
python trust_agent/gateway/app/service.py --port 8787 --db trust_agent/experiments/guard.db
```

The installer preserves unrelated hooks. Existing installations with only a
PreToolUse hook must be upgraded: reads now become context only after completion.
The checked-in live_demo_repo settings already include the three events. The
external trustagent-demo installation is not automatically changed by this patch.

## Protocol

- `POST /decide`: session_id, tool_use_id, op, target, cwd, channel, args.
  HTTP always treats this as a proposed action. Identical retries return the
  original decision; reuse of the ID with different input is denied.
- `POST /complete`: session_id, tool_use_id, boolean success. Only successful,
  previously allowed attempts enter the provenance store. Completion is idempotent.
- `GET /events?session_id=...`: chronological decision/completion audit, with
  decision IDs, evidence IDs, source paths, policy version, and latency.
- `POST /kill`: revoke the session's modeled tool access.

SQLite persists confirmed records, attempts, completion state, audit, and kills.
UUID record IDs avoid overwriting older history when the service restarts.
Raw tool argument bodies are not stored in the decision journal. Paths and
inferred source references remain visible; logs should still be treated as
potentially sensitive metadata. Brain access is serialized across HTTP workers.

The direct Python API retains the old no-phase observed-event convention for
existing tests/callers. New sensors must use the before/complete lifecycle.
The observation daemon remains separate; its transcript events do not feed the
enforcement store.

## Evidence and limits

Evidence distinguishes recorded context, proposed shell references, and inferred
graph/session relationships. Confidence 0.4 is a policy heuristic, not a measured
probability. Shell parsing remains conservative and approximate. Successful
shell commands may mention a file without consuming it, and failed commands may
have partially executed. Grep/Glob directory events do not identify every file
whose contents appeared. Fine-grained result adapters remain necessary.

Unknown tools are denied until a sensor policy models them. Filename-based labels
and the default workspace trust policy remain approximations. Root checkout
provenance should be supplied through an explicit origin policy for a real deployment.

The proxy requires an explicit --session (or AIRLOCK_SESSION) matching the agent.
It checks plain HTTP methods/bodies and never follows redirects without a new
client request. HTTPS CONNECT exposes only the destination; upload classification
there depends on the tool hook. Proxy routing is still optional in this checkout.
Docker network isolation, managed process termination, authentication of sensors,
Codex support, and a dashboard are still separate integration work. STOP revokes
tool access; it does not terminate an already-running process.
