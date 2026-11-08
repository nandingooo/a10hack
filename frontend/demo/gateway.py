"""TrustAgent gateway: serves the dashboard and supervises the demo agents.

Local mode (default) listens on loopback only. Public mode (TRUSTAGENT_PUBLIC=1) is meant for a
server: anyone can watch, operators run. See security.py and the README for the settings."""
import json
import os
import security
import signin
import shutil
import signal
import tempfile
from provider import TASKS, build_prompt, cli_args
BASE_AGENTS = set(TASKS)
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABELS = {
    "iris.csv": ("trusted", "public"),
    "review.json": ("untrusted", "sensitive"),
    "sample-token.txt": ("unknown", "secret"),
    "canary.txt": ("trusted", "secret+bait"),
}
# Session -> subtask -> cooperating agents.
PLAN = {
    "Iris morphology analysis": {
        "Compare petal length and width by species": ["Petal analyst", "Summary writer"],
        "Report sepal width ranges by species": ["Range analyst"],
    },
    "Data quality assessment": {
        "Review schema, class balance, and missing values": ["Sample auditor", "Schema reviewer"],
        "Identify duplicate observations": ["Duplicate checker"],
    },
    "Data transfer policy review": {"Verify transfer restrictions for tagged data": ["Reviewer"]},
}
MAX_SUBTASKS = 5


def prepare_sessions(plan, run_id):
    if sum(map(len, plan.values())) > MAX_SUBTASKS:
        raise ValueError("A console run supports at most five subtasks.")
    sessions, agents = {}, {}
    for task, subtasks in plan.items():
        session_id = f"{run_id}/{task}"
        sessions[session_id] = dict(task=task, subtasks=subtasks, queue=[])
        for subtask, members in subtasks.items():
            for name in members:
                if name in agents:
                    raise ValueError(f"Duplicate agent assignment: {name}")
                agents[name] = dict(status="Running", session_id=session_id, subtask=subtask,
                                    provider=TASKS.get(name, ("Local",))[0])
    return sessions, agents


lock = threading.RLock()
state = {"id": 0, "running": False, "agents": {}, "sessions": {}, "events": []}
workers = {}
# Run limits live outside the published state.
limits = {"last_start": 0.0, "day": "", "runs_today": 0}
snapshot_cache = {"at": 0.0, "body": b""}


class Refused(Exception):
    """A request the gateway understood but will not carry out. status is the HTTP code."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def record(agent, action, target, verdict, reason, labels=None):
    member = state["agents"][agent]
    event = dict(session_id=member["session_id"], subtask=member["subtask"], agent=agent, action=action, target=target, verdict=verdict,
                 reason=reason, labels=labels, time=time.strftime("%H:%M:%S"))
    state["events"].append(event)
    return {"verdict": verdict}


def decide(agent, msg):
    action, target = msg["action"], msg["target"]
    member = state["agents"][agent]
    session = state["sessions"][member["session_id"]]
    if action == "read" and target in LABELS:
        trust, sensitivity = LABELS[target]
        tags = dict(agent=agent, file=target, trust=trust, sensitivity=sensitivity)
        session["queue"].append(tags)
        if sensitivity == "secret+bait":
            member["status"] = "Stopped"
            return record(agent, action, target, "STOP", "Canary access terminated this session.", tags)
        reply = record(agent, action, target, "ALLOW", "File metadata appended to the session queue.", tags)
        reply["content"] = (ROOT / "data" / target).read_text()
        return reply
    if action == "result":
        return record(agent, action, target, "ALLOW", msg["detail"])
    if action in ("export", "model request"):
        reasons = [e["file"] for e in session["queue"] if e["trust"] != "trusted" or e["sensitivity"] != "public"]
        if reasons:
            return record(agent, action, target, "BLOCK", "Session history restricts this transfer: " + ", ".join(reasons))
        if action == "model request" and agent in TASKS and target == TASKS[agent][0]:
            return record(agent, action, target, "ALLOW", "Approved provider; session history contains only trusted public data.")
        if action == "export" and target == "local-report":
            return record(agent, action, target, "ALLOW", "Trusted public summary approved for the local report.")
        return record(agent, action, target, "BLOCK", "Destination is outside the approved local workspace.")
    return record(agent, action, target, "BLOCK", "Operation outside this agent’s permissions.")


def supervise(agent, run_id):
    proc = None
    try:
        with lock:
            if run_id != state["id"] or not state["running"]:
                return
            proc = subprocess.Popen([sys.executable, "-I", str(ROOT / "agent.py"), agent],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, start_new_session=True)
            workers[agent] = proc
        for line in proc.stdout:
            with lock:
                if run_id != state["id"] or not state["running"]:
                    break
                reply = decide(agent, json.loads(line))
            proc.stdin.write(json.dumps(reply) + "\n")
            proc.stdin.flush()
        proc.wait()
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()
        with lock:
            if run_id == state["id"]:
                workers.pop(agent, None)
                session = state["agents"][agent]
                if session["status"] == "Running":
                    session["status"] = "Complete" if proc and proc.returncode == 0 else "Failed"
                state["running"] = any(a["status"] == "Running" for a in state["agents"].values())


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_provider(agent, run_id):
    provider, task = TASKS[agent]
    args = cli_args(provider)
    status = "Failed"
    with tempfile.TemporaryDirectory() as directory:
        try:
            with lock:
                if state["id"] != run_id or state["agents"][agent]["status"] != "Running":
                    return
                if not shutil.which(args[0]):
                    status = "Setup needed"
                    record(agent, "setup", provider, "INFO", "Install and sign in to " + args[0] + " on the gateway host.")
                    return
                data = decide(agent, dict(action="read", target="iris.csv"))
                verdict = decide(agent, dict(action="model request", target=provider))
                if verdict["verdict"] != "ALLOW":
                    status = "Blocked"
                    return
                proc = subprocess.Popen(args, cwd=directory, start_new_session=True,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True)
                workers[agent] = proc
            try:
                output, _ = proc.communicate(build_prompt(task, data["content"]), timeout=120)
            except subprocess.TimeoutExpired:
                kill_group(proc)
                proc.wait()
                raise RuntimeError("Provider timed out after 120 seconds.")
            with lock:
                if state["id"] != run_id or state["agents"][agent]["status"] != "Running":
                    return
                if proc.returncode or not output.strip():
                    raise RuntimeError("Provider returned no successful answer. Check CLI login, network and quota.")
                record(agent, "result", agent, "ALLOW", output.strip()[:4000])
                status = "Complete"
        except (OSError, RuntimeError) as exc:
            with lock:
                if state["id"] == run_id and state["agents"][agent]["status"] == "Running":
                    record(agent, "error", provider, "ERROR", str(exc))
        finally:
            with lock:
                if state["id"] == run_id:
                    workers.pop(agent, None)
                    if state["agents"][agent]["status"] == "Running":
                        state["agents"][agent]["status"] = status
                    state["running"] = any(a["status"] == "Running" for a in state["agents"].values())


def add_agent(payload):
    session = state["sessions"].get(payload.get("session"))
    provider = payload.get("provider")
    subtask = payload.get("subtask")
    if not session or subtask not in session["subtasks"] or provider not in ("Claude Code", "Codex"):
        raise Refused(400, "Choose a current session, subtask, and provider.")
    if sum(1 for name in TASKS if name not in BASE_AGENTS) >= security.MAX_EXTRA_AGENTS:
        raise Refused(409, f"This workspace already has the maximum of {security.MAX_EXTRA_AGENTS} added agents.")
    index = 1
    while f"{provider} assistant {index}" in state["agents"]:
        index += 1
    name = f"{provider} assistant {index}"
    TASKS[name] = (provider, subtask)
    # Session subtask assignments come from PLAN and carry into subsequent runs.
    session["subtasks"][subtask].append(name)
    state["agents"][name] = dict(status="Ready", session_id=payload["session"],
                                 subtask=subtask, provider=provider)
    record(name, "assigned", subtask, "INFO", "Assigned to the next run.")


def start():
    if state["running"]:
        return
    now = time.time()
    wait = int(limits["last_start"] + security.RUN_COOLDOWN - now + 0.999)
    if wait > 0:
        raise Refused(429, f"The next run can start in {wait} s.")
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    if limits["day"] != today:
        limits.update(day=today, runs_today=0)
    if security.MAX_RUNS_PER_DAY and limits["runs_today"] >= security.MAX_RUNS_PER_DAY:
        raise Refused(429, f"The daily limit of {security.MAX_RUNS_PER_DAY} runs is used up. Try again tomorrow (UTC).")
    limits.update(last_start=now, runs_today=limits["runs_today"] + 1)
    run_id = state["id"] + 1
    sessions, agents = prepare_sessions(PLAN, run_id)
    state.update(id=run_id, running=True, events=[], sessions=sessions, agents=agents)
    for name in agents:
        threading.Thread(target=run_provider if name in TASKS else supervise, args=(name, state["id"]), daemon=True).start()


def stop():
    for name, proc in list(workers.items()):
        if proc.poll() is None:
            kill_group(proc)
    for name, session in state["agents"].items():
        if session["status"] == "Running":
            session["status"] = "Stopped"
            record(name, "stop", "session", "STOP", "Stopped by operator.")
    state["running"] = False


def published_state():
    """Serialized state shared by every viewer. Re-encoded at most four times a second so many
    open dashboards polling together cost one encode, not one each."""
    now = time.time()
    if now - snapshot_cache["at"] > 0.25:
        wait = max(0, int(limits["last_start"] + security.RUN_COOLDOWN - now + 0.999)) if not state["running"] else 0
        data = dict(state, public=security.PUBLIC, next_run_in=wait)
        snapshot_cache.update(at=now, body=json.dumps(data).encode())
    return snapshot_cache["body"]


class Handler(SimpleHTTPRequestHandler):
    server_version = "TrustAgent"
    sys_version = ""
    timeout = 20  # seconds a client may stay silent; stops idle connections from piling up

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT.parent / "dist"), **kwargs)

    def send_json(self, data, status=200):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        if self.path.startswith(("/api/", "/auth/")):
            return self.send_json({"error": message or self.responses.get(code, ("Error",))[0]}, code)
        super().send_error(code, message, explain)

    # The page must always be fresh: a cached index.html points at asset files an older build
    # had, which 404 after a rebuild. Hashed /assets/ files never change, so they cache forever.
    def is_page(self):
        return self.path.split("?")[0] in ("/", "/index.html")

    def send_response(self, code, message=None):
        self.status_code = code
        super().send_response(code, message)

    def end_headers(self):
        if getattr(self, "status_code", 0) == 200:
            if self.is_page():
                self.send_header("Cache-Control", "no-cache")
            elif self.path.startswith("/assets/"):
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        security.security_headers(self)
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404)  # never show folder listings

    def log_message(self, fmt, *args):
        if security.PUBLIC or os.getenv("TRUSTAGENT_ACCESS_LOG") == "1":
            sys.stderr.write("%s - [%s] %s\n" % (security.client_ip(self), self.log_date_time_string(), fmt % args))

    def do_GET(self):
        if self.path.startswith("/auth/"):
            return signin.handle(self)  # signin keeps its own lock and calls providers outside it
        if self.path.split("?")[0] == "/api/state":
            with lock:
                if not security.PUBLIC and state["id"] == 0:
                    start()  # local mode starts the first run when the dashboard opens
                return self.send_json(published_state())
        if self.path.startswith("/api/"):
            return self.send_error(404)
        if not (ROOT.parent / "dist" / "index.html").exists():
            return self.send_error(503, "The dashboard is not built. Run npm install and npm run build.")
        if self.is_page():
            del self.headers["If-Modified-Since"]  # file dates can be wrong after unzipping; never answer 304 here
        super().do_GET()

    def do_POST(self):
        if self.path.startswith("/auth/"):
            return signin.handle(self)  # signin keeps its own lock and calls providers outside it
        if self.headers.get("X-Airlock-Demo") != "1" or not security.same_origin(self):
            return self.send_error(403, "Cross-site request refused.")
        if self.path not in ("/api/start", "/api/stop", "/api/add-agent"):
            return self.send_error(404)
        if not signin.can_operate(self):
            user = signin.current_user(self)
            return self.send_error(403 if user else 401, "Only workspace operators can change runs."
                                   if user else "Sign in as a workspace operator to run agents.")
        if not security.api_writes.allow(security.client_ip(self)):
            return self.send_error(429, "Too many requests. Slow down and try again in a minute.")
        payload = None
        if self.path == "/api/add-agent":
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 < length <= 4096:
                    raise ValueError()
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict) or not all(isinstance(payload.get(k), str) for k in ("session", "subtask", "provider")):
                    raise ValueError()
            except (ValueError, UnicodeError):
                return self.send_error(400, "Invalid agent assignment")
        with lock:
            try:
                if self.path == "/api/start":
                    start()
                elif self.path == "/api/add-agent":
                    add_agent(payload)
                else:
                    stop()
            except Refused as refused:
                return self.send_error(refused.status, str(refused))
            except ValueError as exc:
                return self.send_error(400, str(exc))
            snapshot_cache["at"] = 0  # the caller sees its own change immediately
            self.send_json(published_state())


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    max_clients = 200

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.slots = threading.BoundedSemaphore(self.max_clients)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)  # too many open connections: drop instead of spawning more threads
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    if security.PUBLIC and not os.getenv("TRUSTAGENT_ACCESS_CODE"):
        print("Operator access code (set TRUSTAGENT_ACCESS_CODE to keep it across restarts):", signin.code, flush=True)
    else:
        print("Workspace sign-in code:", signin.code if not security.PUBLIC else "(from TRUSTAGENT_ACCESS_CODE)", flush=True)
    for line in security.describe():
        print(line, flush=True)
    Server((security.BIND, security.PORT), Handler).serve_forever()
