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
from dataclasses import asdict, dataclass

import docker
from docker.errors import APIError, NotFound

log = logging.getLogger("sandbox")

LABEL_SESSION = "a10.session_id"
LABEL_ROLE = "a10.role"
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

    @staticmethod
    def _names(session_id: str) -> tuple[str, str]:
        if not SESSION_ID_RE.match(session_id):
            raise ValueError(f"invalid session id: {session_id!r}")
        return f"a10-sbx-{session_id}", f"a10-net-{session_id}"

    def create(self, session_id: str, env: dict[str, str] | None = None) -> SandboxInfo:
        container_name, network_name = self._names(session_id)
        labels = {LABEL_SESSION: session_id}
        token = secrets.token_urlsafe(32)

        # internal=True: no gateway/NAT to the outside world.
        network = self.client.networks.create(
            network_name,
            driver="bridge",
            internal=True,
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
                labels={**labels, LABEL_ROLE: "agent"},
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
        log.info("destroyed sandbox %s", container_name)

    def _remove_network(self, network) -> None:
        network.reload()
        for c in network.containers:  # detach the gateway first
            try:
                network.disconnect(c, force=True)
            except APIError:
                pass
        network.remove()

    def list(self) -> list[dict]:
        out = []
        for c in self.client.containers.list(all=True, filters={"label": f"{LABEL_ROLE}=agent"}):
            out.append(
                {"session_id": c.labels.get(LABEL_SESSION), "container": c.name, "status": c.status}
            )
        return out

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
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    mgr = SandboxManager()
    if args.cmd == "create":
        print(json.dumps(asdict(mgr.create(args.session_id)), indent=2))
    elif args.cmd == "destroy":
        mgr.destroy(args.session_id)
    elif args.cmd == "list":
        print(json.dumps(mgr.list(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
