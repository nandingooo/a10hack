# Monitoring full agent activity + multi-agent provenance

Design note for AgentAirlock. Two decisions, both confirmed:
1. **Monitoring:** get full Claude Code activity + a daemon by **integrating with Agent_Inspection** (the "Waystation / Agent Tower" project), not by rebuilding a daemon.
2. **Multi-agent:** **design + stub now**, build the full cross-session graph in the tree phase.

---

## 1. Monitoring via Agent_Inspection (the daemon we reuse)

Agent_Inspection already provides, in TypeScript:
- **Discovery** — scans Claude Code session files + process liveness; a process scanner for other CLIs. (`daemon/collectors/claudeSessions.ts`, `observedProcesses.ts`)
- **Full-activity capture** — `JsonlTailer` tails each session's transcript `projects/<slug(cwd)>/<sessionId>.jsonl`; `normalizeClaudeLine` emits `AgentEvent{kind: prompt|assistant|tool_call|tool_result|status|stop|system|error}`. This captures **everything the agent does**, observe-only, no hooks needed.
- **Live interception** — `hooks/installer.ts` installs `PreToolUse`/`PostToolUse`/`UserPromptSubmit`/`Stop`/`SessionStart`/`SessionEnd` into `~/.claude/settings.json`; `InterceptionManager` holds a `PreToolUse` call (up to 600s) for allow / edit / deny / ask; `SessionFlags` is a fast file-based per-session intercept switch.
- **Subagents** (parent/child) and **teams** — shared task board (`channels/board.ts`), inter-agent messaging (`notify/*`), git-worktree sandboxes.

**Split of responsibility:** Agent_Inspection is the eyes + hands (monitor + intercept); AgentAirlock is the brain (label + decide).

### The adapter (what we build)
A thin bridge so Agent_Inspection's event stream drives AgentAirlock's `/decide`:

```
AgentEvent (from transcript tail OR PreToolUse hook)
     -> map to DecideRequest { session_id, channel, op, target, origin, args }
     -> POST /decide  (AgentAirlock gateway: label -> store -> aggregate -> verdict)
     -> on PreToolUse: feed verdict into InterceptionManager (allow / deny+message)
```

**AgentEvent -> ContextEntry mapping:**
| AgentEvent | AgentAirlock |
|---|---|
| `prompt` (UserPromptSubmit) | a `trusted` source (the user's instruction) |
| `tool_call` name = Read / Write / Edit / Bash / WebFetch / MCP | `ReadFile` / `WriteFile` / `RunCommand` / `NetworkRequest` / `CallTool` |
| **`tool_result`** | the content the model actually ingested — label by the tool's origin (WebFetch result -> `web`/untrusted). Richer than labeling the file read alone. |
| `stop` / `SessionEnd` | session close |

**Control tiers (theirs) map to our enforcement:**
- Tier A (managed) / Tier B (hooked) -> we can **block** via the PreToolUse hold.
- Tier C (observe-only) -> we **label + record** only (no block). Honest on the badge.

**Why not rebuild:** their transcript tail already gives whole-session activity for free, their hook bridge already does the hold-for-decision we need for STOP/BLOCK, and their teams layer already implements the multi-agent world below. We add the one thing they lack: provenance labeling and the trifecta/bait decision.

---

## 2. Multi-agent / inter-agent-communication provenance

### The problem
Per-session isolation is correct for *ambient* separation (A reading untrusted must not taint B for no reason). But agents **communicate**, and that is a real data-flow edge:

> A reads a secret -> sends B a channel message / shares a worktree file / delegates context -> B exfiltrates. B "never touched" the secret, so session isolation **misses** the leak.

So inter-agent communication must be a **first-class provenance edge**, or cross-agent laundering is invisible.

### The model (stubbed now in `provenance/multiagent.py`)
1. **New origins** (trust is *derived*, not static policy):
   - `agent:<senderId>` — a message, delegation, or forked context from another agent.
   - `shared:<resource>` — a shared conduit: task board, team channel, shared worktree file.
2. **Taint-on-ingest** (`derive_inbound_labels(sender_aggregate)`): when B ingests an inter-agent message or shared read, it inherits the **sender's worst taint at send time** — untrusted if the sender `reached_untrusted`, secret if `reached_secret`, bait if `reached_bait`. Confidence is `< 1.0` (0.8) because the edge is inferred.
3. **Cross-agent trifecta:** the block rule now spans agents — untrusted-or-secret that *arrived from another agent* + an exit = block, even though the receiving agent never read the original file.
4. **Shared conduits:** the writing agent stamps provenance onto the shared item; readers inherit the max taint of its writers.
5. **Globally-unique entry ids** (`new_entry_id(session, seq)` -> `"<session>:eN"`): required so the tree phase can draw `parents` edges **across** sessions, forming one global provenance graph.

### Queue MVP vs tree phase
- **MVP:** on an inter-agent ingest, the caller looks up the sender session's `aggregate()` and calls `derive_inbound_labels(...)` to label the inbound entry. Simple cross-session *lookup*; no graph yet.
- **Tree phase:** the inbound entry gets `parents` pointing at the sender's contributing entries (true cross-session edges); `aggregate()` becomes `trace_back()` across the global graph; `confidence` is the weakest hop.

### Honest caveats
- Cross-agent edges are **inferred** (we see that a message/artifact moved, not its exact bytes), hence sub-1.0 confidence and the "ask a human" path on low confidence.
- Shared-worktree file flows need file-lineage edges (who wrote the file) — that lands with the tree phase's `parents` heuristics.
- This is a genuine differentiator for the pitch: **provenance that follows data across a whole team of agents, not just within one.**

---

## 3. Build order
1. Extend the stream/event mapping to **all** tool types (not just Read) — quick, observe-only.
2. Adapter: Agent_Inspection `AgentEvent` -> `/decide`; wire verdict into `InterceptionManager` for live BLOCK/STOP.
3. Multi-agent: call `derive_inbound_labels` on inter-agent ingests (channel messages, shared reads) using the sender's `aggregate()`.
4. Tree phase: global provenance graph with cross-session `parents` + `trace_back()`.

## 4. Status in code
- Stubs shipped: `gateway/app/provenance/multiagent.py` (`derive_inbound_labels`, `is_cross_agent_origin`, `new_entry_id`, origin constants) + `tests/test_multiagent.py`.
- Not built yet: the TS adapter, the `/decide` endpoint (P1), the tree/global graph.
