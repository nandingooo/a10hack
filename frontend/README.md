# TrustAgent

## Start the included dashboard

From this folder run `python3 demo/gateway.py` (Python 3.8+). Open http://localhost:8787. The bundled dist directory contains the compiled React app. To put it on a server for other people, see [Public deployment](#public-deployment). The landing page starts the first run and displays its output. Click Run again to repeat it. Console shows the same run and adds a collapsible action inspector. The theme button remembers your selection.

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

The gateway prints a workspace access code at startup. Enter it on the Sign in page to sign in as the operator. In local mode signing in is optional and anyone who can open the page can run agents. In public mode the code (or an allowlisted OAuth identity) is required to start, stop or add agents. Sessions expire after eight hours or on restart.

The Sign in page also lists Google (any Gmail or Google Workspace account), GitHub, and AWS Builder ID.

AWS Builder ID needs no setup. It uses the OAuth device-code flow against AWS (oidc.us-east-1.amazonaws.com): the page shows a short code, you confirm it on the AWS page it links to, and the page signs you in once you approve. The gateway host needs outbound HTTPS to AWS, so it does not work inside the offline Docker sandbox. Set TRUSTAGENT_AWS_BUILDER_ID=0 to turn it off.

Google and GitHub are listed as Setup needed until you configure TRUSTAGENT_GOOGLE_CLIENT_ID / TRUSTAGENT_GOOGLE_CLIENT_SECRET or TRUSTAGENT_GITHUB_CLIENT_ID / TRUSTAGENT_GITHUB_CLIENT_SECRET on the gateway host. Set TRUSTAGENT_ORIGIN to the exact browser origin (default http://127.0.0.1:8787). Google sign-in asks for the email scope so the identity can be allowlisted and register that origin plus /auth/callback/google or /auth/callback/github with the provider. Restart the gateway and use that same origin for login.

## Public deployment

`python3 demo/gateway.py` on its own is a single-user local demo: it listens on loopback and anyone who can open the page can run agents. Set `TRUSTAGENT_PUBLIC=1` to run it on a server that other people reach:

| | Local mode (default) | Public mode (`TRUSTAGENT_PUBLIC=1`) |
|---|---|---|
| Listens on | 127.0.0.1 | 0.0.0.0 |
| Watching runs | Anyone with the page | Anyone with the page |
| Start, stop, add agents | Anyone with the page | Operators only |
| First run | Starts when the page opens | Waits for an operator |
| Run cooldown / daily cap | none | 60 s / 50 runs (UTC day) |
| Added agents | 12 | 4 |

Always on, in both modes: POSTs must carry the `X-Airlock-Demo` header and come from the same origin; wrong access codes are limited to 10 per IP per 15 minutes; sign-in flows to 20 per IP per 10 minutes; API writes to 30 per IP per minute; folder listings are off; responses carry a Content-Security-Policy and other security headers; idle connections time out after 20 s and at most 200 are open at once.

**Who is an operator.** Anyone who enters the access code, plus OAuth identities listed in `TRUSTAGENT_OPERATORS`. Anyone else who signs in with Google, GitHub or AWS Builder ID is a viewer.

### Settings

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTAGENT_PUBLIC` | `0` | `1` turns on public mode. |
| `TRUSTAGENT_ORIGIN` | `http://127.0.0.1:8787` | The exact address people open (scheme, host, port). Used for OAuth callbacks and the same-origin check. With `https://` the session cookie is marked Secure and HSTS is sent. |
| `TRUSTAGENT_ACCESS_CODE` | random at each start | Operator code, at least 12 characters. Set it on a server so it survives restarts. |
| `TRUSTAGENT_OPERATORS` | empty | Comma-separated identities that may operate: `github:<login>`, `google:<email>`, `aws:<email>`. |
| `PORT` / `AIRLOCK_BIND` | `8787` / mode default | Listening port and address. |
| `TRUSTAGENT_RUN_COOLDOWN` | `60` public, `0` local | Seconds between runs. |
| `TRUSTAGENT_MAX_RUNS_PER_DAY` | `50` public, unlimited local | Runs per UTC day. `0` means unlimited. |
| `TRUSTAGENT_MAX_EXTRA_AGENTS` | `4` public, `12` local | Agents that can be added on top of the plan. |
| `TRUSTAGENT_TRUST_PROXY` | `0` | `1` when a reverse proxy you run adds `X-Forwarded-For`, so rate limits see real client IPs. Leave it off otherwise: clients could fake the header. |
| `TRUSTAGENT_ACCESS_LOG` | `0` | `1` logs requests in local mode too (public mode always logs). |

### On an Amazon Linux 2023 server (EC2)

1. Launch an instance and allow inbound TCP 8787 in its security group (or 443 if you add HTTPS below).
2. Connect and start the gateway:

   ```bash
   sudo dnf install -y git
   git clone -b Nandingoo/frontend https://github.com/nandingooo/a10hack.git
   cd a10hack/frontend
   TRUSTAGENT_PUBLIC=1 TRUSTAGENT_ORIGIN=http://<public-ip>:8787 TRUSTAGENT_ACCESS_CODE=<long-random-code> python3 demo/gateway.py
   ```

3. To keep it running after you disconnect and across reboots, use the systemd unit in `deploy/` (instructions are at the top of `deploy/trustagent.service`).
4. The six provider agents need the `claude` and `codex` CLIs installed and signed in on the server, under the same user that runs the gateway. Until then they show Setup needed and the local Reviewer still runs. Every run uses that account's quota, which is why runs are limited to operators.

### HTTPS

Without HTTPS the access code and session cookie cross the network in plain text. The simplest fix is Caddy in front of the gateway with a domain name pointing at the server:

```bash
caddy reverse-proxy --from your.domain.example --to 127.0.0.1:8787
```

Then run the gateway with `AIRLOCK_BIND=127.0.0.1 TRUSTAGENT_TRUST_PROXY=1 TRUSTAGENT_ORIGIN=https://your.domain.example`, open ports 80 and 443 instead of 8787, and register `https://your.domain.example/auth/callback/<provider>` with Google or GitHub.

### Docker

`docker build -t trustagent . && docker run -p 8787:8787 -e TRUSTAGENT_PUBLIC=1 -e TRUSTAGENT_ORIGIN=http://<host>:8787 -e TRUSTAGENT_ACCESS_CODE=<code> trustagent`. The image builds the dashboard itself. It contains neither provider CLI, so only the local Reviewer completes there.

### What public mode does not do

There is one shared workspace: everyone watches the same run and the same event log. The run state, sessions and sign-ins live in memory and reset on restart. The demo agents are fixed programs; running untrusted third-party agents still needs an external enforcement boundary (see Fixture and policy above).
