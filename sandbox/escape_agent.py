"""Hostile test agent. Runs INSIDE a sandbox and tries to get out.

Stdlib only. Takes one JSON argument:
  {"gateway": "gateway:8080" | null, "peers": [{"name":..., "ip":...}],
   "host_ips": ["172.17.0.1", ...]}
Prints {"results": [{"check", "expect", "outcome", "ok", "detail"}]} to stdout.

expect "blocked": the attempt must fail. expect "allowed": a control that must work
(proves the harness itself isn't broken). ok = outcome matched expect.
"""

import errno
import json
import os
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 2.0
results = []


def record(check, expect, got_through, detail=""):
    outcome = "allowed" if got_through else "blocked"
    results.append(
        {"check": check, "expect": expect, "outcome": outcome, "ok": outcome == expect, "detail": str(detail)[:200]}
    )


def tcp(host, port):
    """True if a packet reached the target: connected, or actively refused."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True, "connected"
    except ConnectionRefusedError:
        return True, "refused (target reachable)"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"


def tcp_check(name, host, port, expect="blocked"):
    reached, detail = tcp(host, port)
    record(name, expect, reached, f"{host}:{port} {detail}")


def resolves(name):
    try:
        return True, socket.gethostbyname(name)
    except OSError as e:
        return False, e


def dns_udp_direct(server):
    # Hand-built query for example.com A; escape only if a reply comes back.
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(q, (server, 53))
        s.recvfrom(512)
        return True, "got DNS reply"
    except OSError as e:
        return False, e
    finally:
        s.close()


def network_checks(cfg):
    jobs = [
        lambda: tcp_check("internet: tcp 1.1.1.1:443", "1.1.1.1", 443),
        lambda: tcp_check("internet: tcp 8.8.8.8:53", "8.8.8.8", 53),
        lambda: record("internet: resolve example.com", "blocked", *resolves("example.com")),
        lambda: record("internet: raw UDP DNS to 8.8.8.8", "blocked", *dns_udp_direct("8.8.8.8")),
        lambda: tcp_check("cloud metadata 169.254.169.254", "169.254.169.254", 80),
        lambda: record("resolve host.docker.internal", "blocked", *resolves("host.docker.internal")),
    ]
    for ip in cfg.get("host_ips", []):
        for port in (22, 80, 2375, 2376, 9000):
            jobs.append(lambda ip=ip, port=port: tcp_check(f"host {ip}:{port}", ip, port))
    for peer in cfg.get("peers", []):
        jobs.append(lambda p=peer: record(f"peer resolve {p['name']}", "blocked", *resolves(p["name"])))
        for port in (22, 80, 8080):
            jobs.append(lambda p=peer, port=port: tcp_check(f"peer {p['name']} {p['ip']}:{port}", p["ip"], port))
    if cfg.get("gateway"):
        host, port = cfg["gateway"].rsplit(":", 1)
        jobs.append(lambda: tcp_check("CONTROL gateway reachable", host, int(port), expect="allowed"))
    with ThreadPoolExecutor(32) as pool:
        list(pool.map(lambda f: f(), jobs))


def try_(fn):
    try:
        return True, fn()
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def status_field(name):
    for line in open("/proc/self/status"):
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def write_file(path, data="x"):
    with open(path, "w") as f:
        f.write(data)
    return f"wrote {path}"


def exec_copy(dir_):
    dst = os.path.join(dir_, "probe-bin")
    shutil.copy("/bin/true", dst)
    os.chmod(dst, 0o755)
    subprocess.run([dst], check=True, timeout=5)
    return f"executed {dst}"


def host_mounts():
    allowed_points = {"/etc/resolv.conf", "/etc/hostname", "/etc/hosts"}
    host_fs = {"ext4", "xfs", "btrfs", "virtiofs", "9p", "nfs", "nfs4", "fuse.grpcfuse", "fakeowner"}
    found = []
    for line in open("/proc/self/mountinfo"):
        left, right = line.split(" - ", 1)
        point, fstype = left.split()[4], right.split()[0]
        if fstype in host_fs and point not in allowed_points:
            found.append(f"{point} ({fstype})")
    if found:
        return found
    raise RuntimeError("no host filesystems mounted")


def child(code, timeout=30):
    """Run code in a child python; True if it completed normally."""
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    if r.returncode == 0:
        return True, r.stdout.strip()
    return False, f"exit {r.returncode} {r.stderr.strip()[-120:]}"


def system_checks():
    record("running as root", "blocked", os.getuid() == 0, f"uid={os.getuid()}")
    cap = status_field("CapEff")
    record("has Linux capabilities", "blocked", int(cap or "0", 16) != 0, f"CapEff={cap}")
    nnp = status_field("NoNewPrivs")
    record("can gain privileges (setuid)", "blocked", nnp != "1", f"NoNewPrivs={nnp}")
    record("docker socket present", "blocked", *try_(lambda: os.stat("/var/run/docker.sock") and "exists"))
    record("write to root filesystem", "blocked", *try_(lambda: write_file("/etc/escape-probe")))
    record("write /proc/sysrq-trigger", "blocked", *try_(lambda: write_file("/proc/sysrq-trigger", "h")))
    record("read /etc/shadow", "blocked", *try_(lambda: open("/etc/shadow").read(1)))
    record("open raw socket", "blocked",
           *try_(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()))
    record("mount a filesystem", "blocked",
           *try_(lambda: subprocess.run(["mount", "-t", "tmpfs", "none", "/mnt"], check=True,
                                        capture_output=True, timeout=5) and "mounted"))
    record("host filesystem mounted", "blocked", *try_(host_mounts))
    record("execute binary from /tmp", "blocked", *try_(lambda: exec_copy("/tmp")))
    record("execute binary from workdir", "blocked", *try_(lambda: exec_copy("/home/agent/work")))
    record("CONTROL scratch dir writable", "allowed", *try_(lambda: write_file("/home/agent/work/probe")))


def resource_checks():
    record("allocate 1 GiB memory (limit 512m)", "blocked",
           *child("b = bytearray(1024**3); b[::4096] = b'x' * len(b[::4096]); print('allocated')"))
    record("start 400 threads (pids limit 256)", "blocked", *child(
        "import threading, time\n"
        "ts = [threading.Thread(target=time.sleep, args=(5,), daemon=True) for _ in range(400)]\n"
        "[t.start() for t in ts]\nprint('started 400')"))
    record("fill /tmp with 100 MiB (limit 64m)", "blocked", *child(
        "f = open('/tmp/fill', 'wb')\n"
        "[f.write(b'0' * 1024**2) for _ in range(100)]\nf.flush(); print('wrote 100MiB')"))
    try:
        os.remove("/tmp/fill")
    except OSError:
        pass


def main():
    cfg = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    network_checks(cfg)
    system_checks()
    resource_checks()
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
