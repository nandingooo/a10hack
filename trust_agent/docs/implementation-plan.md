# Harness completion plan

The active scope is all four stages below. Unit tests alone do not prove sandbox
enforcement or live-agent reliability. Record direct evidence for each stage.

1. Authoritative source policy and resource identity; inherited labels across
   derived/copied/moved artifacts and sessions; classification reasons in evidence.
2. Separate attempts, execution and exposure; partial-failure propagation;
   unresolved-operation restrictions; transactional persistence, retry, concurrency,
   and restart verification.
3. Managed launcher and sandbox; protected control plane; forced and attributed
   egress; STOP terminates the sandbox and connections. Verify real execution.
4. Task/resource policies and live evidence UI; allowed work, denied continuation,
   and actual termination. Distinguish live-agent evidence from synthetic tests.

No stage is complete based only on intent, command construction or narrower tests.

## Completion evidence (verified 2026-11-07, source layer)

- Source suite: 118 passed, 1 skipped, 1 xfailed (skip needs Windows symlink
  privilege; xfail is the documented `tree_store` placeholder).
- End-to-end wiring confirmed: `hook.py` (Pre/Post/PostFailure/PermissionDenied) ->
  `service.py` (`/decide`,`/complete`,`/events`,`/network`,`/kill`,`/enforcement`) ->
  `engine.Brain` -> store -> `mediated_network` broker.
- Gap closures verified by test:
  - Web content modeled as an untrusted source; web -> exfil to an unapproved host
    blocks as `lethal_trifecta` (`tests/test_web_provenance.py`).
  - Copy/move label inheritance across sessions (`test_exposure_lifecycle.py`).
  - Confirmed provenance: failed/denied reads do not taint (`test_confirmed_policy.py`).
  - URL-query and header exfiltration channels (`test_exposure_lifecycle.py`).
  - `secret_upload` containment to approved hosts; task/network-capability scoping.
- William-compat: `SqliteStore` still exposes `sessions(id,status)` ACTIVE/KILLED and
  `evidence(session)` -> (last untrusted id, last secret id).
- Demo repo `trustagent-demo` upgraded to the full lifecycle via
  `sandbox/install_hooks.py`.

## Residual limitations (by design / fundamental -- stated, not hidden)

- The decision uses a conservative session-level label union as the floor; graph
  parents are carried as evidence, not as the gate. This never under-blocks; it can
  over-block unrelated actions. Precise `trace_back` gating is deliberately NOT the
  decider, because a missed inferred edge would under-block a security control.
- Shell exposure is an over-approximation. A shell command cannot be fully parsed
  (interpreters can read any readable file), so strict mode assumes a `RunCommand`
  may read the whole workspace and cannot downgrade its exposure. Over-blocks by
  design rather than miss a read.
- HTTPS `CONNECT` exposes only the destination host. Upload bodies are inspected
  only on the typed `/network` broker path (method, body, headers, query, size,
  redirects, private-destination rejection). Raw tunnelled HTTPS body content is not
  inspected; containment there relies on the host allowlist + secret-context block.
- `confidence 0.4` on inferred/inherited edges is a policy heuristic, not a measured
  probability.

## Remaining operational work (requires runtime / operator -- not code)

1. Rebuild images (running containers predate current source):
   `docker build -f sandbox/Dockerfile.gateway -t trustagent-gateway:local .` and
   `docker build -f sandbox/Dockerfile.agent -t trustagent-agent:local .`
   (or re-run `airlock.py run ...`, which builds via compose).
2. One real authenticated Claude session: allowed work -> accumulated context ->
   attempted unsafe continuation blocked -> STOP terminates the container. Record it.
3. Publish branch `codex/harness-wip` (push requires operator approval).
