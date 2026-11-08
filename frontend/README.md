# TrustAgent

## Start the included dashboard

From this folder run `python3 demo/gateway.py` (Python 3.8+). Open http://localhost:8787. The bundled dist directory contains the compiled React app. The landing page starts the first run and displays its output. Click Run again to repeat it. Console shows the same run and adds a collapsible action inspector. The theme button remembers your selection.

## Shared Docker sandbox

With Docker Desktop running, use `docker compose up --build` from this folder instead. Visit the same address. Both CLI workers run as separate Python processes inside one container, supervised by the demo gateway. Compose configures an internal network and a loopback port. End with `docker compose down`.

## Fixture and policy

The Analyst computes mean petal length by species from 150 Iris observations bundled from scikit-learn (https://scikit-learn.org/stable/modules/generated/sklearn.datasets.load_iris.html). The Reviewer reads synthetic tagged fixtures, requests an export, and touches a canary. No outbound transfer is performed. Per-task session queues and verdicts live in memory for the current run. Run again replaces the previous demo. The dashboard polls the gateway every 450 ms.

These are deterministic Python task agents, with no model API key requirement. The gateway mediates their cooperative RPC operations. This demo shares its container with the workers and is designed for the bundled programs only. Running third-party agents requires an external enforcement boundary, identity, and interception of their actual tools and network traffic.

## Edit React

Keep the Python gateway running. In a second terminal, install dependencies and run Vite with Node 22.12 or newer. Vite proxies /api to port 8787. Run npm run build after edits to regenerate dist for Python or Docker.

## Seven-agent provider board (current version)

The landing page starts six real CLI calls (three Claude Code, three Codex) plus the local Reviewer on its first load. These calls use the provider accounts and quota of the machine running the gateway. Install and authenticate both CLIs there. Run the Python gateway locally for this mode: the stock offline Docker image contains neither provider CLI and cannot contact their services.

Each provider has three distinct Iris tasks. Its adapter reads the labeled public fixture and requests gateway approval before passing data to the CLI. The gateway supervises adapter operations and collects final answers; it does not intercept all internal provider CLI activity. A missing executable shows Setup needed; a failed call shows Failed. There is no simulated provider output.

The Console groups seven agents into three task sessions and five subtasks total. Session members share labeled history. The inspector filters events by session ID, and the terminal filters them again by agent.

## Sign in

The gateway prints a workspace access code at startup. Enter it on the Sign in page to sign in as the local operator. This is an optional profile for a shared local demo; the demo API remains publicly accessible on loopback. Sessions expire after eight hours or on restart.

The Sign in page also lists Google (any Gmail or Google Workspace account), GitHub, and AWS Builder ID.

AWS Builder ID needs no setup. It uses the OAuth device-code flow against AWS (oidc.us-east-1.amazonaws.com): the page shows a short code, you confirm it on the AWS page it links to, and the page signs you in once you approve. The gateway host needs outbound HTTPS to AWS, so it does not work inside the offline Docker sandbox. Set TRUSTAGENT_AWS_BUILDER_ID=0 to turn it off.

Google and GitHub are listed as Setup needed until you configure TRUSTAGENT_GOOGLE_CLIENT_ID / TRUSTAGENT_GOOGLE_CLIENT_SECRET or TRUSTAGENT_GITHUB_CLIENT_ID / TRUSTAGENT_GITHUB_CLIENT_SECRET on the gateway host. Set TRUSTAGENT_ORIGIN to the exact browser origin (default http://127.0.0.1:8787) and register that origin plus /auth/callback/google or /auth/callback/github with the provider. Restart the gateway and use that same origin for login.
