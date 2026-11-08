"""Where may the gateway send traffic on an agent's behalf?

The gateway has network access the sandbox doesn't (internet, the Docker host, cloud
metadata). Without this check an agent could ask the gateway to fetch
http://169.254.169.254/... or http://host.docker.internal:9000/... and reach internal
services *through* the gateway. Only public internet addresses on allowed ports pass.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
BLOCKED_NAMES = {"localhost", "gateway", "a10-gateway", "host.docker.internal",
                 "gateway.docker.internal", "metadata.google.internal", "metadata"}


def _bad_ip(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if not addr.is_global or addr.is_multicast:
        return f"{addr} is not a public internet address"
    return None


def check_destination(url: str, offline: bool, resolve=socket.getaddrinfo) -> tuple[str | None, str]:
    """Returns (reason_if_blocked, host). Resolves names and checks every address."""
    try:
        u = urlparse(url)
        port = u.port
    except ValueError:
        return "malformed URL", ""
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme not in ALLOWED_SCHEMES:
        return f"scheme '{u.scheme}' not allowed", host
    if not host:
        return "no host", host
    if u.username or u.password:
        return "credentials in URL not allowed", host
    if (port or (443 if u.scheme == "https" else 80)) not in ALLOWED_PORTS:
        return f"port {port} not allowed", host
    if host in BLOCKED_NAMES or host.endswith(".localhost"):
        return f"{host} is an internal name", host
    if reason := _bad_ip(host):
        return reason, host
    try:
        addrs = {ai[4][0] for ai in resolve(host, None)}
    except (OSError, UnicodeError):
        # Offline placeholder: nothing is actually sent, so unresolvable demo hosts are fine.
        return (None, host) if offline else (f"cannot resolve {host}", host)
    for a in addrs:
        if reason := _bad_ip(a):
            return f"{host} resolves to {reason}", host
    return None, host
