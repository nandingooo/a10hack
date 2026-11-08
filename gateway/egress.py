"""Where may the gateway send traffic on an agent's behalf?

The gateway has network access the sandbox doesn't (internet, the Docker host, cloud
metadata). Without this check an agent could ask the gateway to fetch
http://169.254.169.254/... or http://host.docker.internal:9000/... and reach internal
services *through* the gateway. Only public internet addresses on allowed ports pass.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import httpx

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


@dataclass
class Checked:
    reason: str | None  # set = blocked
    host: str
    addrs: list[str] = field(default_factory=list)  # the vetted addresses to connect to


def check_destination(url: str, offline: bool, resolve=socket.getaddrinfo) -> Checked:
    """Resolves names and checks every address. Connect only to `addrs` afterwards."""
    try:
        u = urlparse(url)
        port = u.port
    except ValueError:
        return Checked("malformed URL", "")
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme not in ALLOWED_SCHEMES:
        return Checked(f"scheme '{u.scheme}' not allowed", host)
    if not host:
        return Checked("no host", host)
    if u.username or u.password:
        return Checked("credentials in URL not allowed", host)
    if (port or (443 if u.scheme == "https" else 80)) not in ALLOWED_PORTS:
        return Checked(f"port {port} not allowed", host)
    if host in BLOCKED_NAMES or host.endswith(".localhost"):
        return Checked(f"{host} is an internal name", host)
    if reason := _bad_ip(host):
        return Checked(reason, host)
    if _is_ip(host):
        return Checked(None, host, [host])
    try:
        addrs = {ai[4][0] for ai in resolve(host, None)}
    except (OSError, UnicodeError):
        # Offline placeholder: nothing is actually sent, so unresolvable demo hosts are fine.
        return Checked(None, host) if offline else Checked(f"cannot resolve {host}", host)
    for a in addrs:
        if reason := _bad_ip(a):
            return Checked(f"{host} resolves to {reason}", host)
    return Checked(None, host, sorted(addrs, key=lambda a: ":" in a))  # IPv4 first


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def pinned_request(client: httpx.Client, method: str, url: str, checked: Checked,
                   max_bytes: int, **kw) -> tuple[int, dict, bytes]:
    """Send the request to the address that was checked, not to a fresh DNS answer.

    The URL's host is replaced by the vetted IP; the Host header and TLS SNI keep the
    original name, so virtual hosting and certificate checks still work. A DNS server
    that answers differently on the second lookup (rebinding) never gets asked.
    Redirects are not followed (the agent must request the new URL, which is re-checked),
    and at most max_bytes of the body are read.
    """
    if not checked.addrs:
        raise ValueError("destination was not resolved")
    u = urlparse(url)
    ip = checked.addrs[0]
    netloc = (f"[{ip}]" if ":" in ip else ip) + (f":{u.port}" if u.port else "")
    pinned = urlunparse(u._replace(netloc=netloc))
    headers = {**kw.pop("headers", {}), "Host": u.hostname + (f":{u.port}" if u.port else ""),
               "Accept-Encoding": "identity"}  # so max_bytes caps real bytes
    req = client.build_request(method, pinned, headers=headers,
                               extensions={"sni_hostname": u.hostname}, **kw)
    resp = client.send(req, stream=True, follow_redirects=False)
    try:
        body = b""
        for chunk in resp.iter_bytes():
            body += chunk
            if len(body) >= max_bytes:
                body = body[:max_bytes]
                break
        hdrs = {k: v for k, v in resp.headers.items() if k.lower() in ("content-type", "location")}
        return resp.status_code, hdrs, body
    finally:
        resp.close()
