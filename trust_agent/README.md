# TrustAgent

A local harness for supervised Claude Code sessions. The guard labels exposed
context by integrity and confidentiality, accumulates those labels, and evaluates
tool actions and network operations before execution. A provenance graph and audit
explain recorded observations and conservative inferences.

## Run a managed session

Prerequisites: Python 3.11+, Docker Engine 28+ with Compose, and PyYAML 6.0.2.
The container build installs the pinned Claude CLI. Interactive login uses the
unmodified CLI and a private per-session Docker volume.

```powershell
python -m pip install -r trust_agent/requirements.txt
python trust_agent/airlock.py run --repo trust_agent/experiments/live_demo_repo --port 8797 --detach
python trust_agent/airlock.py login SESSION_ID
python trust_agent/airlock.py chat SESSION_ID
```

Open the local evidence interface in a separate terminal:

```powershell
python trust_agent/airlock.py dashboard --port 8798
```

Use the printed local operator URL. STOP terminates both the agent container and
gateway and verifies that they have stopped. It also terminates interactive exec
sessions and child processes. Revoked sessions are not resumed as active sessions.

See [interactive rehearsal](docs/interactive-rehearsal.md) for login, prompts,
network requirements and cleanup considerations.

## What is enforced

- The agent has a read-only root, an isolated internal Docker network, a writable
  workspace snapshot, a private identity volume and root-owned managed hooks.
- All external network access goes through the gateway. Unmodeled encrypted
  destinations are denied; the authentication/model provider has explicit receiver
  authority. The agent has neither the Docker socket nor operator credentials.
- Repository origin defaults to untrusted. Derived/copied/moved artifact labels
  persist in the provenance namespace; explicit operator authority is required
  for privileged operations. Labels are not cleared merely because an inferred
  graph path is absent.
- Attempts, execution results and exposure are separate. Failures can expose
  information; missing completion restricts consequential actions. SQLite commits
  lifecycle and provenance together, with retry and restart support.
- Secret context can prohibit uploads to otherwise approved hosts. URL queries,
  headers, opaque tunnels and task-specific resource scope are evaluated.

For scoped HTTP(S) operations that need URL-level authorization, use the typed
broker from inside the sandbox:

```sh
python3 /opt/airlock/sandbox/request.py https://github.com
```

`run --allow-public-upload https://host/project` defines POST/PUT/PATCH authority
for that host/path subtree. It does not authorize secret disclosure, and the host
must also be in policy. An opaque TLS tunnel cannot exercise this URL permission;
the typed broker constructs the request, pins destination resolution, verifies
TLS and does not implicitly follow redirects.

## Verify

```powershell
python -m pytest trust_agent/tests -q
python trust_agent/experiments/provenance_demo.py
python trust_agent/experiments/verify_sandbox.py SESSION_ID
```

The sandbox verifier targets the scripted rehearsal after it has read `.env`.
Launch that rehearsal with an explicit command:

```powershell
python trust_agent/airlock.py run --repo trust_agent/experiments/live_demo_repo --port 8797 --detach -- python3 /opt/airlock/sandbox/demo_agent.py
```

It performs real hook/file operations but makes no language-model calls. Browser
verification additionally requires Chrome and Python websockets 15; it intentionally
stops the selected rehearsal run. Live-model evidence is recorded separately.

## Limits

Shell execution is opaque: its conservative exposure includes readable workspace
and private runtime resources. This can over-block legitimate shell uploads.
File/search interpretation is approximate; the graph records known and inferred
relationships rather than proving exact LLM causality. Trusted sensor reporting
and the configured model receiver are security assumptions. The standalone hook
or local service alone does not provide the managed sandbox's containment.

The operator deliberately authorizes the model provider to receive context. The
forward proxy checks TLS destinations, not encrypted provider payloads. This is
an experimental harness, not universal prompt-injection prevention.
