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
import ipaddress
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 2.0
results = []


def pool_map(fn, items, workers):
    """Thread pool that shrinks instead of crashing when the sandbox's process limit is
    exhausted (e.g. by sibling agents' limit probes)."""
    items = list(items)
    while True:
        try:
            with ThreadPoolExecutor(workers) as pool:
                return list(pool.map(fn, items))
        except RuntimeError:
            if workers == 1:
                raise
            workers = max(1, workers // 4)
            __import__("time").sleep(1)


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
    done = set()

    def run(job):
        i, f = job
        if i not in done:
            f()
            done.add(i)

    pool_map(run, enumerate(jobs), 32)


def own_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("gateway", 9))  # no packet sent; just picks the interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def subnet_scan(cfg):
    """Every address in our /24: only the gateway (and us) may answer."""
    me = own_ipv4()
    if not me:
        return record("scan sandbox subnet: only gateway answers", "allowed", False, "no IPv4 address")
    try:
        gw_ip = socket.gethostbyname("gateway")
    except OSError:
        gw_ip = None
    net = ipaddress.ip_network(f"{me}/24", strict=False)
    targets = [str(h) for h in net.hosts() if str(h) not in (me, gw_ip)]

    def probe(ip):
        # One port is enough: a host that exists answers (connect or refuse) on any port.
        try:
            with socket.create_connection((ip, 80), timeout=1):
                return ip
        except ConnectionRefusedError:
            return ip
        except OSError:
            return None

    found = [ip for ip in pool_map(probe, targets, 40) if ip]
    record("scan sandbox subnet: anything besides gateway", "blocked", bool(found),
           f"{len(targets)} addresses scanned; answered: {found[:5]}")


def gateway_request(path, body=None):
    gw = os.environ.get("GATEWAY_URL", "http://gateway:8080")
    req = urllib.request.Request(gw + path, method="GET" if body is None else "POST",
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + os.environ.get("SESSION_TOKEN", ""),
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:150].decode(errors="replace")
    except OSError as e:
        return 0, str(e)


SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://host.docker.internal:9000/sessions",
    "http://127.0.0.1:8080/admin/alerts",
    "http://localhost/",
    "http://2130706433/",
    "http://[::1]/",
    "http://172.17.0.1/",
    "http://10.0.0.1/",
    "http://gateway:8080/admin/alerts",
    "file:///etc/passwd",
]


def gateway_checks(cfg):
    if not cfg.get("gateway"):
        return
    code, detail = gateway_request("/admin/alerts")
    record("gateway admin API from sandbox", "blocked", code == 200, f"HTTP {code} {detail}")
    if not cfg.get("gateway_tools"):
        return
    code, detail = gateway_request("/tools/list_files")
    record("CONTROL gateway tools work", "allowed", code == 200, f"HTTP {code} {detail}")
    for url in SSRF_TARGETS:
        code, detail = gateway_request("/tools/fetch_url", {"url": url})
        record(f"via gateway: fetch {url.split('/')[2] if '//' in url else url}", "blocked",
               code == 200, f"HTTP {code} {detail}")


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
    dst = os.path.join(dir_, f"probe-bin-{os.getpid()}")
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
    seccomp = status_field("Seccomp")
    record("syscall filter (seccomp) off", "blocked", seccomp != "2", f"Seccomp={seccomp}")
    v6 = [l.split()[-1] + " " + l.split()[0] for l in open("/proc/net/if_inet6")
          if l.split()[-1] != "lo"] if os.path.exists("/proc/net/if_inet6") else []
    record("has IPv6 address", "blocked", bool(v6), v6 or "no IPv6")
    record("create user namespace (unshare)", "blocked",
           *try_(lambda: os.unshare(os.CLONE_NEWUSER) or "unshared"))
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
    record("CONTROL scratch dir writable", "allowed", *try_(lambda: write_file(f"/home/agent/work/probe-{os.getpid()}")))


def cgroup_limit(name, default):
    try:
        v = open(f"/sys/fs/cgroup/{name}").read().strip()
        return default if v == "max" else int(v)
    except OSError:
        return default


def resource_checks():
    mem_mib = cgroup_limit("memory.max", 512 * 2**20) // 2**20 + 256
    pids = cgroup_limit("pids.max", 256) + 100
    st = os.statvfs("/tmp")
    tmp_mib = st.f_blocks * st.f_frsize // 2**20 + 32
    record("allocate past memory limit", "blocked", *child(
        f"b = bytearray({mem_mib} * 2**20); b[::4096] = b'x' * len(b[::4096]); print('allocated {mem_mib} MiB')"))
    record("exceed process limit", "blocked", *child(
        "import threading, time\n"
        f"ts = [threading.Thread(target=time.sleep, args=(5,), daemon=True) for _ in range({pids})]\n"
        f"[t.start() for t in ts]\nprint('started {pids}')"))
    record("fill /tmp past its size", "blocked", *child(
        f"f = open('/tmp/fill-{os.getpid()}', 'wb')\n"
        f"[f.write(b'0' * 2**20) for _ in range({tmp_mib})]\nf.flush(); print('wrote {tmp_mib} MiB')"))
    try:
        os.remove(f"/tmp/fill-{os.getpid()}")
    except OSError:
        pass


def main():
    cfg = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    network_checks(cfg)
    subnet_scan(cfg)
    gateway_checks(cfg)
    system_checks()
    resource_checks()
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
