# AgentAirlock implemented scope

[PR #3](https://github.com/nandingooo/a10hack/pull/3) · `william/stateful-guard` · Snapshot at `25f0020`

## How the guard runs

The guard is a long-running FastAPI service. A trusted sensor submits a pending action. The guard checks the session status, looks up relevant prior results in SQLite, records the verdict, and returns `allow`, `block`, or `stop` with a rule ID, reason, and any supporting evidence IDs. The caller enforces the verdict before forwarding the action.

SQLite stores session status, sensor-token hashes, and an ordered history of decisions, outcomes, and operator stops. A read contributes evidence only when a trusted sensor records that data was made available to the agent. An approved read and a failed read that returns no data leave the exposure state unchanged. History is scoped to the session and survives service restarts. The guard stores metadata and labels, with raw file contents and outbound bodies excluded from the audit log.

## Implemented decisions

| Rule | Trigger | Verdict | Uses prior evidence? |
|---|---|---|---|
| `invalid_target` | A file operation supplies a path that is outside the accepted absolute, normalized format. | `BLOCK` | No |
| `outside_workspace` | A file operation targets a path outside the configured workspace. | `BLOCK` | No |
| `protected_path` | A write or deletion targets the workspace root or `.git` tree. | `BLOCK` | No |
| `egress_allowlist` | A network request supplies an invalid or unapproved hostname. | `BLOCK` | No |
| `untrusted_destructive` | A mediated `DeleteFile` request follows an observed read that returned untrusted data in the same run. | `BLOCK` | Yes. The response links the prior result. |
| `secret_external_write` | The demo MCP tool `post_support_update` is called after an observed read that returned secret data in the same run. | `BLOCK` | Yes. The response links the prior result. A harmless message can also be blocked under this broad rule. |
| `bait_touched` | A file operation targets a configured canary filename, or the inspected outbound body contains the fixed canary token. | `STOP` | No |
| `operator_stop` | The operator calls the session stop endpoint. | Session becomes `KILLED`. | No |
| `session_killed` | A sensor submits an action for a stopped session. | `STOP` with HTTP 403 | Uses the saved session status. |
| `unsupported_action` | An operation has no implemented policy. Examples include generic shell and model calls. | `BLOCK` | No |
| `policy_allows` | A supported action passes the applicable checks. | `ALLOW` | Depends on the action. |

The guard can call the existing sandbox termination API when configured. It saves `KILLED` before requesting termination. If the sandbox request fails, the session stays closed and the operator can retry termination.

## How earlier results change a decision

These examples assume an active session and actions that pass the baseline checks. The guard considers results from that same session. If it blocks the pending action, the agent can still make other requests in the run.

### Untrusted read followed by a workspace deletion

| What happens | Why the guard allows or blocks it |
|---|---|
| The agent reads a cloned `README.md`. | **Allow.** Reading repository docs is a normal part of coding. The guard records the returned content as untrusted because it came from the cloned repo. |
| The agent requests `DeleteFile` for `/home/agent/work/build/report.json` in a run with no recorded untrusted read. | **Allow.** The path is inside the workspace, outside the protected paths, and a deletion can be ordinary cleanup. |
| The same `DeleteFile` follows the recorded README result. | **Block** with `untrusted_destructive`. Repository content could have instructed the agent to delete the file. The guard links the earlier result so the operator can see what triggered the rule. |

The rule treats any earlier untrusted read as a reason to block a later deletion. It can therefore block legitimate cleanup after an unrelated README read. The linked result shows what the agent saw before the request. Establishing that the README caused the deletion attempt would require additional evidence.

**Evidence.** AgentDojo includes an indirect-injection task that succeeds when the specified file disappears from a simulated cloud drive. In a later controlled evaluation, the deletion succeeded in 44 of 50 trials for one model without the tested defenses. This establishes that retrieved content can induce destructive tool use in a benchmark. The policy implication for AgentAirlock is to verify authority for the specific file, such as a user-approved target or a sandbox record that the run created it as disposable output. [AgentDojo deletion task](https://github.com/ethz-spylab/agentdojo/blob/main/src/agentdojo/default_suites/v1/workspace/injection_tasks.py#L49-L69), [Controlled evaluation, Table A7](https://www.mdpi.com/2079-9292/15/13/2829)

### Secret read followed by an external ticket update

| What happens | Why the guard allows or blocks it |
|---|---|
| The agent reads a workspace `.env` fixture. | **Allow.** The current file policy permits the read. The path is labeled `secret`, and a recorded result that returns the file to the agent establishes exposure. |
| The agent calls `post_support_update` in a run with no recorded secret read. | **Allow.** The registered tool is available for routine updates such as “We reproduced the crash.” |
| The same update follows the recorded `.env` result. | **Block** with `secret_external_write`. The agent has received data labeled secret and is now attempting to write to an external destination. The guard links the secret read result. |

This rule uses the fact that the agent received secret-labeled data. It blocks even an identical, harmless call to the demo support tool because it looks at exposures across the session. A read that failed without returning data leaves the update eligible to proceed. Confirming a leak would require evidence about the outgoing message or what was delivered.

**Evidence.** General Analysis demonstrated that a malicious customer ticket steered a Cursor assistant through Supabase MCP to read a private table and copy sensitive dummy data into a reply the customer could see. Invariant Labs demonstrated a similar flow from a public GitHub issue, through a private repository read, to a public pull request. Both demonstrations involved a concrete flow of private data into a visible destination. [Supabase proof of concept](https://generalanalysis.com/blog/supabase-mcp-blog), [GitHub MCP proof of concept](https://invariantlabs.ai/blog/mcp-github-vulnerability)

**Proposed refinement.** An unrelated user-requested email can be drafted locally. For sending, the gateway could construct an exact user-supplied message or verify approval bound to the final recipient, body, and attachments. A protected attachment or report would need a release policy that permits it at that destination. This would let the guard distinguish user-authorized content from an unapproved transfer. PR #3 currently implements the broader rule for one MCP tool.

`session_killed` uses saved state in a different way. An earlier stop closes the session, so any later action is refused regardless of its tool or target.

## API and tests

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Check that the guard can access its database. |
| `POST /sessions` | Register a session and return a session-specific sensor token to the operator backend. |
| `POST /decide` | Evaluate a pending action. |
| `POST /results` | Record the outcome of an allowed action. An identical result retry returns the original result ID. |
| `GET /sessions/{id}/history` | Read paginated audit events with operator access. |
| `POST /sessions/{id}/stop` | Stop the guard session and request sandbox termination when configured. |

Five API tests cover evidence-based denial, persistence across a restart, session isolation, result retries, the canary, and guard behavior when sandbox termination fails. A live local HTTP smoke test verified that `post_support_update` changes from allow to block after a secret result is recorded. Sandbox termination was tested against a mock API.

## Remaining work for the live demo

- Connect the CLI hook and MCP or egress proxy so real agent actions pass through the guard and follow its decisions.
- Add the proposed cleanup rule based on trusted evidence that the current run created the exact artifact.
- Add the proposed preview deployment rule based on a trusted test result for the exact revision being deployed.
