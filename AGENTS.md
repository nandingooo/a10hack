# AgentAirlock — AGENTS.md (authoritative build spec)

> This is the single source of truth for building AgentAirlock. It is written to be read by **teammates and their coding agents**. It is precise on purpose: schemas, helper definitions, invariants, and acceptance tests are normative. If something here is ambiguous, fix it here first, then build.
>
> Place a copy at repo root as `AGENTS.md` (and symlink/copy to `CLAUDE.md`). Each module folder may contain a 5–10 line `CLAUDE.md` that points here.

**Event:** AWS x A10 Hack · A10 Track · Prompt 2 "Agent Harness".
**Prompt (verbatim):** "Build a control layer for desktop and CLI-based AI agents that routes requests through a central gateway. Demo: Launch a CLI agent, display its traffic, block a disallowed action, and stop the run."
**Status:** MVP uses a **context QUEUE**; graph is a later upgrade (§14). Draft v1, 2026-11-07.

### Implemented protocol revision: exposure-aware managed harness

This revision supersedes conflicting MVP pseudocode below for `trust_agent`.
`gateway/policy/labels.yaml` is the authoritative runtime policy. Repository origin
is explicit and defaults to cloned-repo/untrusted. Resource labels survive derived,
copied and moved artifacts; context labels conservatively accumulate across turns.
The graph explains observations and inferred relationships; it does not prove
that an LLM ignored other context.

HTTP `/decide` evaluates an attempt (`phase=before`, `tool_use_id`, `cwd`).
`/complete` separates boolean execution success from `exposure=none|exposed|unknown`.
Failed and partially completed operations can expose data. Missing completion
restricts consequential work. Attempts, results, exposure and sensor-reported
`/enforcement` acknowledgments have an append-only audit. SQLite commits lifecycle
and provenance changes together. Retried IDs/results must match exactly.

Managed sessions scope writes to the authorized workspace and outbound writes to
operator-defined URL capabilities. Secret context can prohibit disclosure even
to approved hosts (supersedes T12 for writes). Queries and headers are data channels;
opaque HTTPS tunnels require explicit receiver authority. `/network` executes
modeled HTTP(S) requests with destination pinning and no implicit redirects.

Opaque shell execution is conservatively labeled from accessible workspace and
private runtime resources; it cannot report away that inference. Such labels are
not claimed as observed file reads. The exact tool-result path is recorded where
available; shell/search interpretation remains approximate. Confidence scores for
inference are policy heuristics, not calibrated probabilities.

Managed Docker sessions have a private identity volume for Claude's own interactive
login, a read-only root and managed hooks, an internal isolated network and forced
proxy egress. The host supervisor terminates both agent and gateway on STOP and
checks actual stopped state. No Docker socket or operator credential is mounted
into the agent. Interactive login and live-model behavior must be verified
separately from the scripted rehearsal.

The direct Python API keeps a no-phase observed-event mode for existing tests;
managed sensors always use the attempt/result lifecycle. The standalone local
service/hook is not equivalent to the managed sandbox's containment.

---

## 1. What we are building (1 paragraph)

A security harness and control plane for CLI coding agents (Claude Code, Kiro). Each agent runs inside a **Docker sandbox** whose only exits are **sensors** (tool hook, egress proxy, MCP proxy, optional model proxy). Every sensor asks one central **decision service** ("the guard") before an action happens; the guard answers **ALLOW / BLOCK / STOP** by reasoning over the agent's **context provenance**. A **dashboard** shows live traffic, explains each decision, and can stop any agent. Primary threat: **prompt injection**.

## 2. Core principle (do not violate)

We do **not** detect malicious text. We track **where context came from** and block **actions** that mix untrusted input with secrets or an exit. Reading untrusted content is always allowed; only *acting* on it dangerously is blocked. (Basis: CaMeL, FIDES — §Appendix A.)

---

## 3. Glossary (defined terms — agents MUST use these meanings)

- **Agent**: the AI coding CLI being supervised (Claude Code / Kiro). NOT our code.
- **Sensor**: our interception point around the agent (hook / egress / mcp / model). Dumb: it asks the guard and obeys.
- **Guard / decision service**: our central FastAPI service. Plain code. The ONLY thing that decides.
- **Context entry**: one record of something the agent read or did. Stored in the queue. Schema §6.1.
- **Context queue**: per-session append-only list of context entries. The MVP store. §6.1.
- **Sink / action**: an event that can cause harm — `RunCommand`, `NetworkRequest`, `CallTool`, `WriteFile`, `DeleteFile`. Decisions happen at sinks.
- **Source**: an event that brings data in — a `ReadFile`, web fetch, or tool output.
- **Label**: trust + sensitivity classification of an entry. §5.
- **Bait**: a planted fake secret (honeytoken). Touching it = confirmed compromise → STOP.
- **Verdict**: `allow` | `block` | `stop` | `ask`.
- **Helpers** (defined in §7.2): `match()`, `in_ws()`, `approved_host()`, `is_bait_target()`, `classify_origin()`, `label()`.

---

## 4. Invariants (MUST / MUST NOT — these are hard requirements)

1. **MUST fail closed.** If the guard is unreachable, times out, or errors, the sensor returns **BLOCK**.
2. **MUST treat `unknown` trust as `untrusted`.** Never default to trusted.
3. **MUST NOT mutate a context entry after append.** The queue is append-only (it is also the audit log).
4. **MUST NOT evict from the queue for decision purposes.** No sliding-window forgetting. (Cold-storage archival is fine; the decision still sees the full session.)
5. **MUST check the kill switch first** on every `/decide`. A `KILLED` session returns 403/STOP for all requests.
6. **The guard MUST be deterministic.** No LLM call is allowed to produce the final verdict. A model may only set a label/confidence.
7. **MUST tag every request/event with `session_id`.** No un-attributed events.
8. **The agent sandbox MUST have no network route except the egress proxy.** (internal-only Docker network.)
9. **Every verdict MUST carry a human-readable `reason` and the `rule` id.** (For the dashboard "why" and for judges.)

---

## 5. Label model (two independent axes)

Each entry gets one value per axis + flags.

- **trust** (integrity): `trusted` | `untrusted` | `unknown`(→treated as untrusted). "Can it carry instructions?"
- **sensitivity** (confidentiality): `public` | `sensitive` | `secret`. "How bad if it leaks?"
- **flags**: `bait: bool`, `in_workspace: bool`.

**MVP minimum values:** trust ∈ {trusted, untrusted}; sensitivity ∈ {public, secret}; both flags used. `sensitive` and `unknown` may be folded in later.

Labels are **policy** (set by config §7.1), not inferred by an AI.

---

## 6. Data model (strict schemas — normative)

### 6.1 ContextEntry
| field | type | req | default | notes |
|---|---|---|---|---|
| `id` | string | yes | — | e.g. `"e12"`, unique per session |
| `ts` | float (epoch s) | yes | — | |
| `session_id` | string | yes | — | |
| `kind` | enum `source`\|`secret`\|`action` | yes | — | `secret` = a read of a secret-labeled resource |
| `channel` | enum `hook`\|`egress`\|`mcp`\|`model` | yes | — | which sensor |
| `op` | enum `ReadFile`\|`WriteFile`\|`DeleteFile`\|`RunCommand`\|`NetworkRequest`\|`CallTool`\|`ModelCall` | yes | — | |
| `target` | string | yes | — | path, host, or tool name |
| `origin` | enum `user`\|`workspace`\|`cloned-repo`\|`web`\|`tool-output`\|`download`\|`unknown` | yes | `unknown` | feeds trust label |
| `labels` | Labels | yes | — | §5; `{trust,sensitivity,bait,in_workspace}` |
| `action_props` | ActionProps\|null | for `kind=action` | null | `{is_exit:bool,is_destructive:bool}` |
| `verdict` | Verdict\|null | set by guard | null | written after decision |
| `rule` | string\|null | set by guard | null | rule id that fired |
| `parents` | string[] | yes | `[]` | **MVP: always []**. Graph phase: parent entry ids. KEEP THIS FIELD. |

### 6.2 Session
| field | type | req | default |
|---|---|---|---|
| `session_id` | string | yes | — |
| `agent` | enum `claude-code`\|`kiro` | yes | — |
| `role` | enum `developer`\|`reviewer`\|`deployer` | yes | `developer` |
| `status` | enum `ACTIVE`\|`KILLED` | yes | `ACTIVE` |
| `token` | string (JWT) | yes | — |
| `created_at` | float | yes | — |

### 6.3 DecideRequest (sensor → guard)
```
{ session_id: string, channel: enum, op: enum, target: string,
  origin: enum, args: { cmd?: string, host?: string, path?: string, body?: string } }
```
### 6.4 DecideResponse (guard → sensor)
```
{ decision: enum(allow|block|stop|ask), rule: string, reason: string,
  confidence: float(0..1), latency_ms: int }
```
### 6.5 Event (guard → dashboard, over WS)
```
{ type: "event", entry: ContextEntry, session: Session }   // entry includes verdict+rule
{ type: "session", session: Session }                       // on create/kill
```

---

## 7. Policy & helpers

### 7.1 `labels.yaml` (hand-edited policy)
```yaml
trust:
  trusted:   ["user", "operator"]            # matched against origin
  untrusted: ["cloned-repo", "web", "tool-output", "download"]
sensitivity:
  secret:    ["**/.env", "**/.aws/credentials", "**/.ssh/*", "**/*token*", "**/*.pem", "**/id_rsa*"]
  sensitive: ["**/config/*", "**/*.log", "**/customers/*"]
  # everything else -> public
bait:
  files:     ["**/aws_prod_credentials.txt", "**/.env.production.local"]
  token:     "AKIA_FAKE_BAIT_DO_NOT_USE"     # the fake secret value planted in bait files
egress:
  approved_hosts: ["github.com", "pypi.org", "*.pythonhosted.org", "bedrock-runtime.*.amazonaws.com"]
workspace_root: "/work"                        # everything under here is in_workspace
```

### 7.2 Helper definitions (implement exactly; agents MUST NOT invent other behavior)
```
match(path, globs)      -> bool   # true if path matches any glob (fnmatch, '**' = any depth)
in_ws(path)             -> bool   # true if abspath(path) is under cfg.workspace_root
approved_host(host)     -> bool   # true if host matches any cfg.egress.approved_hosts glob
classify_origin(origin) -> trust  # 'trusted' if in cfg.trust.trusted; 'untrusted' if in cfg.trust.untrusted; else 'unknown'->'untrusted'
is_bait_target(event)   -> bool   # true if: (file op) match(event.target, cfg.bait.files)
                                  #        OR (NetworkRequest) cfg.bait.token in (event.args.body or "")
label(path, origin)     -> Labels # trust=classify_origin(origin);
                                  # sensitivity = 'secret' if match(path,cfg.secret) else 'sensitive' if match(path,cfg.sensitive) else 'public';
                                  # bait = match(path, cfg.bait.files); in_workspace = in_ws(path)
```

---

## 8. Decision algorithm (MVP — normative pseudocode)

```python
def decide(session, event) -> DecideResponse:
    t0 = now()
    if session.status == "KILLED":
        return resp("stop", "session_killed", "session already terminated", 1.0, t0)

    append_to_queue(session, event)          # INVARIANT 3,4: append-only, never evicted

    # Bait is checked on EVERY event (read or action): touching bait = confirmed compromise
    if is_bait_target(event):
        kill_session(session)                 # §10 four-layer kill
        return resp("stop", "bait_touched", "bait resource accessed -> hijack confirmed", 1.0, t0)

    if event.kind != "action":
        return resp("allow", "read_recorded", "context read; labeled and recorded", 1.0, t0)

    q = queue(session)
    reached_untrusted = any(e.labels.trust == "untrusted" for e in q)
    reached_secret    = any(e.labels.sensitivity == "secret" for e in q)
    is_exit        = event.op == "NetworkRequest" and not approved_host(event.args.host)
    is_destructive = event.action_props.is_destructive

    # FIDES-style two checks + egress allowlist
    if reached_secret and is_exit:
        return resp("block", "secret_exit", "secret data reaching an unapproved exit", 0.9, t0)
    if reached_untrusted and is_exit:
        return resp("block", "lethal_trifecta", "untrusted input reaching an unapproved exit", 0.9, t0)
    if reached_untrusted and is_destructive:
        return resp("block", "untrusted_destructive", "untrusted input driving a destructive action", 0.8, t0)
    if event.op == "NetworkRequest" and not approved_host(event.args.host):
        return resp("block", "egress_allowlist", "exit to an unapproved host", 1.0, t0)

    return resp("allow", "no_dangerous_flow", "no dangerous provenance detected", 1.0, t0)
```
Notes:
- `is_destructive` is set by the sensor (e.g., `rm -rf`, `git push --force`, `DROP TABLE`, delete outside workspace). Guard trusts the sensor's flag for MVP; define the destructive patterns in the hook (§9.1).
- Network to an **approved** host is allowed even after untrusted/secret reads (that's how a legit `git push` to github survives). This is intentional and keeps over-blocking low. The remaining MVP over-block is rule `untrusted_destructive` firing on an unrelated destructive action — accepted for MVP; graph (§14) fixes it.

---

## 9. Sensor specs

### 9.1 Tool hook (Claude Code `PreToolUse` / Kiro `preToolUse`)
- Reads the tool call JSON on stdin; builds a DecideRequest (`channel:"hook"`).
- Map tool → op: Bash→`RunCommand`, Read→`ReadFile`, Write→`WriteFile`, Edit→`WriteFile`, (delete)→`DeleteFile`, WebFetch→`NetworkRequest`, MCP tool→`CallTool`.
- Set `is_destructive` true if the command matches: `rm -rf`, `git push --force`/`-f`, `DROP TABLE`, `mkfs`, writes/deletes where `not in_ws(path)`. Split compound commands on `;`, `&&`, `|` and flag if ANY part is destructive.
- POST `/decide`. On `block`/`stop`: print reason to stderr, `exit 2` (blocks the tool). On `allow`: `exit 0`. On any error/timeout(5s): `exit 2` (INVARIANT 1).

### 9.2 Egress proxy (mitmproxy addon)
- For each outbound request: DecideRequest (`channel:"egress"`, `op:"NetworkRequest"`, `target`/`args.host` = host, `args.body` = first 64KB of body).
- On `block`/`stop`: return HTTP 403 with the reason. On error: 403 (fail closed).

### 9.3 MCP proxy (optional for MVP)
- Sits between agent and MCP servers. On `tools/list`: record tool fingerprints. On `tools/call`: DecideRequest (`op:"CallTool"`, `target`=tool name). Block = refuse the call.

### 9.4 Model proxy (optional)
- If used, the agent's model base URL points here; forward to Bedrock/Anthropic. On a `KILLED` session return 403 (this is what makes STOP cut the agent's "brain"). Pass the response stream through unchanged.

---

## 10. Kill switch (four layers, fire all on STOP)
1. Session store: `status = KILLED` (every future `/decide` → stop).
2. Model proxy refuses the session.
3. Revoke the agent's token (Cognito client disable / JWT denylist).
4. Daemon `docker kill`s the container.

---

## 11. Acceptance tests (build against these — normative)

Each row: given a session queue state, then an incoming event → expected verdict/rule. `UT`=an untrusted read already in queue; `SEC`=a secret read already in queue.

| # | Queue state | Incoming event | Expect |
|---|---|---|---|
| T1 | empty | ReadFile `README.md` origin=cloned-repo | allow / read_recorded (entry trust=untrusted) |
| T2 | empty | WriteFile `src/app.py` in_ws | allow / no_dangerous_flow |
| T3 | UT(README) | NetworkRequest host=`evil.example` | block / lethal_trifecta |
| T4 | UT(README) | NetworkRequest host=`github.com` | allow / no_dangerous_flow (approved host) |
| T5 | SEC(.env) | NetworkRequest host=`evil.example` | block / secret_exit |
| T6 | empty | NetworkRequest host=`evil.example` | block / egress_allowlist |
| T7 | UT(README) | RunCommand `rm -rf /work` (is_destructive) | block / untrusted_destructive |
| T8 | any | ReadFile `aws_prod_credentials.txt` (bait) | stop / bait_touched |
| T9 | any | NetworkRequest body contains bait token | stop / bait_touched |
| T10 | status=KILLED | any event | stop / session_killed |
| T11 | empty | RunCommand `pytest` | allow / no_dangerous_flow |
| T12 | SEC(.env) | NetworkRequest host=`github.com` | allow (approved host; MVP accepts this) |

Guard code MUST pass T1–T12. Add the laundering test (T13) when the graph lands (§14).

---

## 12. Tech stack & versions

Pin at install; these are known-good floors (verify latest patch at install time):
- **Python** 3.11+ · FastAPI 0.110+ · uvicorn 0.29+ · pydantic 2.x · redis-py 5.x (or SQLite via stdlib) · httpx 0.27+ · PyJWT 2.8+
- **mitmproxy** 10.x · **Docker** engine 24+ / docker-py 7.x
- **Node** 20 LTS · **React** 18.3.1 · **Vite** 5.x · **Tailwind** 3.4.x · **xterm.js** 5.3.x
- AWS (optional): boto3 1.34+, Bedrock, DynamoDB, Verified Permissions, Cognito; CDK 2.x.

**Run (local):**
```
# guard
cd gateway && pip install -r requirements.txt && uvicorn app.main:app --port 8000
# dashboard
cd dashboard && npm i && npm run dev
# launch an agent
airlock run claude --repo ./demo/payments-service
```

---

## 13. Repo structure, ownership & build order

```
agentairlock/
  gateway/   app/{main.py, queue_store.py, labeler.py, rules.py, events.py}  policy/labels.yaml   # P1
  sandbox/   Dockerfile hooks/hook.py egress/addon.py mcp/proxy.py bait/seed.py compose.yaml       # P2
  daemon/    (launch/stop/list, terminal streaming)                                                # P2
  cli/       (airlock run|stop|ps)                                                                 # P2
  dashboard/ (React: feed, why-panel, STOP, xterm terminals, graph later)                          # P3
  demo/      (repo with failing test + planted untrusted file + fake creds + canary host)          # P4
  infra/     (docker-compose, AWS CDK)                                                              # P4
  tests/     (policy tests T1..T12)                                                                 # P1
  AGENTS.md  CLAUDE.md  docs/                                                                       # all
```

**Build order (critical path first):**
1. P1: `/decide` passing T1–T12 with the queue store. P2: hook that calls it and blocks on exit 2.
2. P2: Docker sandbox (internal-only net) + egress proxy. P3: dashboard on mock events.
3. Integrate: sensor → guard → dashboard shows a real deny; STOP works end to end.
4. P2: bait seeding + four-layer kill. P1: labels.yaml wired. P4: demo repo + scenario.
5. P4: AWS swaps where stable; P3: "why" panel + metrics. Then graph (§14) if time.

---

## 14. Upgrade path: queue → graph (post-MVP, keep it cheap)
1. Populate `ContextEntry.parents` (empty in MVP) via heuristics: action args contain a known source's text → parent (conf 0.9); action reads a file a prior entry wrote → parent (0.8); recently-read source → parent (0.4).
2. Replace the "scan whole queue" booleans with `trace_back(entry)`: BFS over `parents`, collect reachable labels + weakest-hop confidence + the path.
3. Gains: stops over-blocking (block only if THIS action is connected to the poison), catches **laundering** through intermediate files, yields the exact path for the "why"/graph view (React Flow).
4. Unchanged: `/decide`, labels, rules, sensors. Add acceptance test T13 (laundering: UT→write notes→read notes→exfil → block/lethal_trifecta).

---

## 15. Demo (one motion, hits the 4 required beats)
Launch agent on the booby-trapped repo → live feed fills (traffic) → hijacked agent tries to exfil/touch bait → BLOCK/STOP shown red → click to EXPLAIN (queue entries that led to it) → press STOP (4-layer kill; next request 403). Extras: run with the agent's own safety off (`--yolo`) and still block; run a read-only reviewer agent under the same policy.

## 16. Non-goals / what we do NOT claim
- Not perfect taint tracking (MVP: session-level; graph: source-level with confidence).
- Not protection against pre-existing malware on the host (we guard the agent, not the OS).
- Not a replacement for the agent's built-in safety (independent layer; defense in depth).
- MVP can over-block on unrelated destructive actions; accepted, graph fixes it.

## 17. Open decisions (settle at the hour-1 sync)
1. Demo attack one-hop (queue MVP is enough) vs laundering (prioritize graph §14).
2. Primary agent: Claude Code (recommended) vs Kiro; second agent for the vendor-neutral demo if time.
3. Model routing: Claude Code on Bedrock (real kill switch, best AWS story, test in hour 1) vs normal login.
4. AWS services to swap in: min = DynamoDB + Bedrock; stretch = Verified Permissions (Cedar) + Cognito.
5. Session/queue store: Redis vs SQLite.

---

## Appendix A — research backing (verify IDs before citing)
- **CaMeL** (Google DeepMind, 2025, arXiv:2503.18813, "Defeating Prompt Injections by Design"): trusted-plan / quarantined-data split; enforce at the tool call; untrusted data can't become an action. → our architecture + enforce-at-sink.
- **FIDES** (Microsoft, 2025, arXiv:2505.23643): integrity + confidentiality labels, propagated, checked deterministically at the sink. → our two-axis labels + non-AI guard.
- "Lethal trifecta" (Simon Willison, 2025): untrusted content + private data + exfil channel → our block rule. Honeytokens/canary tokens → our bait.
- **Honest framing:** these instrument the agent internally (per-value taint). We approximate from outside on unmodifiable CLIs, at source level, with confidence. We complement, not integrate.

## Appendix B — why A10 cares (for the pitch, not the build)
Same philosophy as A10 products: inline checkpoint, data plane vs control plane. Extends A10's 2026 AI strategy (AI Gateway; TrojAI: AI firewall, MCP registry, rug-pull detection) to the developer laptop where CLI agents actually run. Vocabulary to use: inline enforcement, policy, audit trail, shadow MCP, rug-pull, fail-closed, p50/p99 latency. Runs self-hosted OR on AWS (A10 sells on-prem/air-gapped).

---
*End. If you change a schema, invariant, or rule, update this file in the same PR.*
