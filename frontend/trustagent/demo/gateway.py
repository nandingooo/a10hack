"""Loopback-only local demo by default. Supervises two fixed Python workers."""
import json
import os
import signin
import shutil
import signal
import tempfile
from provider import TASKS, build_prompt, cli_args
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
        raise ValueError("Choose a current session, subtask, and provider.")
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
    run_id = state["id"] + 1
    sessions, agents = prepare_sessions(PLAN, run_id)
    state.update(id=run_id, running=True, events=[], sessions=sessions, agents=agents)
    for name in agents:
        threading.Thread(target=run_provider if name in TASKS else supervise, args=(name, state["id"]), daemon=True).start()


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT.parent / "dist"), **kwargs)

    def snapshot(self):
        data = json.dumps(state).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/auth/"):
            return signin.handle(self)  # signin keeps its own lock and calls providers outside it
        if self.path == "/api/state":
            with lock:
                return self.snapshot()
        if self.is_page():
            del self.headers["If-Modified-Since"]  # file dates can be wrong after unzipping; never answer 304 here
        super().do_GET()

    def do_POST(self):
        if self.path.startswith("/auth/"):
            return signin.handle(self)  # signin keeps its own lock and calls providers outside it
        if self.headers.get("X-Airlock-Demo") != "1":
            return self.send_error(403)
        with lock:
            if self.path == "/api/start":
                start()
            elif self.path == "/api/add-agent":
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    if not 0 < length <= 4096:
                        raise ValueError()
                    payload = json.loads(self.rfile.read(length))
                    if not isinstance(payload, dict) or not all(isinstance(payload.get(k), str) for k in ("session", "subtask", "provider")):
                        raise ValueError()
                    add_agent(payload)
                except (ValueError, UnicodeError):
                    return self.send_error(400, "Invalid agent assignment")
            elif self.path == "/api/stop":
                for name, proc in list(workers.items()):
                    if proc.poll() is None:
                        kill_group(proc)
                for name, session in state["agents"].items():
                    if session["status"] == "Running":
                        session["status"] = "Stopped"
                        record(name, "stop", "session", "STOP", "Stopped by operator.")
                state["running"] = False
            else:
                return self.send_error(404)
            self.snapshot()


if __name__ == "__main__":
    addr = (os.getenv("AIRLOCK_BIND", "127.0.0.1"), 8787)
    print("Local workspace sign-in code:", signin.code, flush=True)
    print("TrustAgent: http://localhost:8787", flush=True)
    ThreadingHTTPServer(addr, Handler).serve_forever()
