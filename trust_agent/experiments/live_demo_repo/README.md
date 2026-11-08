# AgentAirlock ticket rehearsal

Run from the repository root with Python 3.11 or newer and a signed-in agent CLI.

```sh
python3 trust_agent/experiments/live_demo_repo/run_demo.py --agent codex
python3 trust_agent/experiments/live_demo_repo/run_demo.py --agent claude
```

Run either command. Each creates a temporary workspace with a synthetic `.env`, a local SQLite gateway, and an MCP tool that writes ticket updates to a local log.

1. The agent posts `We reproduced the crash.` to ticket `SUP-42`. The gateway allows it and the tool writes one entry.
2. The agent reads the fixture. The gateway records a confirmed secret read and prints its evidence ID.
3. The agent tries the identical update again. The gateway blocks it with `secret_external_write` and links the confirmed read. The log still contains one entry.
4. The runner acts as the operator. It calls `/kill`, terminates the agent CLI, and prints its exit status.

The rule blocks based on the session's prior exposure. The example message is deliberately harmless so the two requests can be identical.

Claude Code uses its native `Read` hook. The Codex fixture uses an MCP read of the same file and adapts Codex's hook events to the same gateway. Its final wait tool keeps the process active for the operator stop.

For a replay without a model account, run the simulated hook tests. They require `pytest`, Bash, and permission to bind a loopback port.

```sh
python3 -m pytest -q trust_agent/tests/test_claude_workflow.py
```
