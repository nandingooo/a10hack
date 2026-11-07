"""Per-session agent sandboxes on Docker.

Each session gets:
  * its own internal Docker network (no route to the internet or to other sessions),
  * one hardened container (read-only root, no capabilities, non-root, resource caps),
  * a random session token the gateway uses to tell which session a request came from.

The gateway container, if running, is attached to every session network under the
alias "gateway", so the agent reaches it at http://gateway:<port> and nothing else.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import sys
import time
from dataclasses import asdict, dataclass

import docker
from docker.errors import APIError, NotFound

log = logging.getLogger("sandbox")

LABEL_SESSION = "a10.session_id"
LABEL_ROLE = "a10.role"
LABEL_CREATED = "a10.created_at"
SESSION_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


@dataclass
class SandboxConfig:
    image: str = os.getenv("SANDBOX_IMAGE", "a10-agent-sandbox:latest")
    gateway_container: str = os.getenv("GATEWAY_CONTAINER", "a10-gateway")
    gateway_port: int = int(os.getenv("GATEWAY_PORT", "8080"))
    mem_limit: str = os.getenv("SANDBOX_MEM", "512m")
    cpus: float = float(os.getenv("SANDBOX_CPUS", "1.0"))
    pids_limit: int = int(os.getenv("SANDBOX_PIDS", "256"))
    tmpfs_size: str = os.getenv("SANDBOX_TMPFS", "64m")
    command: list[str] | None = None  # None = image default


@dataclass
class SandboxInfo:
    session_id: str
    container_id: str
    container_name: str
    network: str
    gateway_url: str
    session_token: str
    gateway_attached: bool


class SandboxManager:
    def __init__(self, config: SandboxConfig | None = None, client=None):
        self.config = config or SandboxConfig()
        self.client = client or docker.from_env()
        # Last gateway activity per session. In memory only: after a restart, idle time
        # counts from process start so live sessions are not reaped straight away.
        self.last_seen: dict[str, float] = {}
        self.started_at = time.time()

    @staticmethod
    def _names(session_id: str) -> tuple[str, str]:
        if not SESSION_ID_RE.match(session_id):
            raise ValueError(f"invalid session id: {session_id!r}")
        return f"a10-sbx-{session_id}", f"a10-net-{session_id}"

    def create(self, session_id: str, env: dict[str, str] | None = None) -> SandboxInfo:
        container_name, network_name = self._names(session_id)
        labels = {LABEL_SESSION: session_id}
        created = time.time()
        token = secrets.token_urlsafe(32)

        # internal=True: no NAT to the outside world.
        # inhibit_ipv4: the host gets no IP on this bridge. Without it the sandbox can
        # reach host services (sshd, the sandbox API, ...) via the bridge gateway IP,
        # because traffic to the host's own addresses is never forwarded or filtered.
        network = self.client.networks.create(
            network_name,
            driver="bridge",
            internal=True,
            options={"com.docker.network.bridge.inhibit_ipv4": "true"},
            labels={**labels, LABEL_ROLE: "network"},
        )
        try:
            gateway_attached = self._attach_gateway(network)
            gateway_url = f"http://gateway:{self.config.gateway_port}"

            container = self.client.containers.run(
                self.config.image,
                command=self.config.command,
                name=container_name,
                detach=True,
                network=network_name,
                hostname="sandbox",
                labels={**labels, LABEL_ROLE: "agent", LABEL_CREATED: str(int(created))},
                environment={
                    **(env or {}),
                    "SESSION_ID": session_id,
                    "SESSION_TOKEN": token,
                    "GATEWAY_URL": gateway_url,
                },
                user="10001:10001",
                read_only=True,
                tmpfs={
                    "/tmp": f"rw,noexec,nosuid,size={self.config.tmpfs_size}",
                    "/home/agent/work": f"rw,noexec,nosuid,uid=10001,size={self.config.tmpfs_size}",
                },
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=self.config.mem_limit,
                memswap_limit=self.config.mem_limit,
                nano_cpus=int(self.config.cpus * 1e9),
                pids_limit=self.config.pids_limit,
                init=True,
                auto_remove=False,
            )
        except Exception:
            self._remove_network(network)
            raise

        info = SandboxInfo(
            session_id=session_id,
            container_id=container.id,
            container_name=container_name,
            network=network_name,
            gateway_url=gateway_url,
            session_token=token,
            gateway_attached=gateway_attached,
        )
        self.last_seen[session_id] = created
        log.info("created sandbox %s", container_name)
        return info

    def _attach_gateway(self, network) -> bool:
        try:
            gateway = self.client.containers.get(self.config.gateway_container)
        except NotFound:
            log.warning(
                "gateway container %r not running; sandbox will have no network peers",
                self.config.gateway_container,
            )
            return False
        network.connect(gateway, aliases=["gateway"])
        return True

    def destroy(self, session_id: str) -> None:
        container_name, network_name = self._names(session_id)
        try:
            self.client.containers.get(container_name).remove(force=True)
        except NotFound:
            pass
        try:
            self._remove_network(self.client.networks.get(network_name))
        except NotFound:
            pass
        self.last_seen.pop(session_id, None)
        log.info("destroyed sandbox %s", container_name)

    def _remove_network(self, network) -> None:
        network.reload()
        for c in network.containers:  # detach the gateway first
            try:
                network.disconnect(c, force=True)
            except APIError:
                pass
        network.remove()

    def _agent_containers(self):
        return self.client.containers.list(all=True, filters={"label": f"{LABEL_ROLE}=agent"})

    @staticmethod
    def _summary(c) -> dict:
        return {
            "session_id": c.labels.get(LABEL_SESSION),
            "container": c.name,
            "status": c.status,
            "created_at": c.attrs.get("Created"),
        }

    def list(self) -> list[dict]:
        return [self._summary(c) for c in self._agent_containers()]

    def get(self, session_id: str) -> dict | None:
        container_name, _ = self._names(session_id)
        try:
            return self._summary(self.client.containers.get(container_name))
        except NotFound:
            return None

    def resolve_token(self, token: str) -> str | None:
        """Return the session id that owns this token, or None.

        The token lives only in the container's environment, so the mapping survives
        restarts of this process without a separate store.
        """
        for c in self._agent_containers():
            env = c.attrs.get("Config", {}).get("Env") or []
            stored = next((e.split("=", 1)[1] for e in env if e.startswith("SESSION_TOKEN=")), None)
            if stored and secrets.compare_digest(stored, token):
                session_id = c.labels.get(LABEL_SESSION)
                self.touch(session_id)
                return session_id
        return None

    def touch(self, session_id: str) -> None:
        """Record activity so the idle timeout restarts."""
        self.last_seen[session_id] = time.time()

    def reap(
        self,
        max_age: float | None = None,
        idle_timeout: float | None = None,
        now: float | None = None,
    ) -> list[dict]:
        """Destroy sandboxes that exited, are older than max_age, or idle past idle_timeout.

        Also removes session networks whose container is gone. Returns what was removed.
        """
        now = time.time() if now is None else now
        reaped = []
        live = set()
        for c in self._agent_containers():
            session_id = c.labels.get(LABEL_SESSION)
            created = float(c.labels.get(LABEL_CREATED, now))
            idle_since = self.last_seen.get(session_id, max(created, self.started_at))
            reason = None
            if c.status in ("exited", "dead"):
                reason = f"container {c.status}"
            elif max_age is not None and now - created > max_age:
                reason = f"older than {max_age:.0f}s"
            elif idle_timeout is not None and now - idle_since > idle_timeout:
                reason = f"idle for over {idle_timeout:.0f}s"
            if reason:
                self.destroy(session_id)
                reaped.append({"session_id": session_id, "reason": reason})
            else:
                live.add(session_id)

        for net in self.client.networks.list(filters={"label": f"{LABEL_ROLE}=network"}):
            session_id = (net.attrs.get("Labels") or {}).get(LABEL_SESSION)
            if session_id not in live and not any(r["session_id"] == session_id for r in reaped):
                try:
                    self._remove_network(net)
                    reaped.append({"session_id": session_id, "reason": "orphaned network"})
                except (APIError, NotFound):
                    pass

        for r in reaped:
            log.info("reaped %s: %s", r["session_id"], r["reason"])
        return reaped

    def exec(self, session_id: str, cmd: list[str]) -> tuple[int, str]:
        container_name, _ = self._names(session_id)
        result = self.client.containers.get(container_name).exec_run(cmd, user="10001:10001")
        return result.exit_code, result.output.decode(errors="replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage per-session agent sandboxes")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create"); p.add_argument("session_id")
    p = sub.add_parser("destroy"); p.add_argument("session_id")
    sub.add_parser("list")
    p = sub.add_parser("reap", help="remove exited, orphaned, or too-old sandboxes")
    p.add_argument("--max-age", type=float, default=float(os.getenv("SANDBOX_MAX_AGE", "7200")))
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    mgr = SandboxManager()
    if args.cmd == "create":
        print(json.dumps(asdict(mgr.create(args.session_id)), indent=2))
    elif args.cmd == "destroy":
        mgr.destroy(args.session_id)
    elif args.cmd == "list":
        print(json.dumps(mgr.list(), indent=2))
    elif args.cmd == "reap":
        # No idle check here: activity is only tracked inside the API process.
        print(json.dumps(mgr.reap(max_age=args.max_age), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
