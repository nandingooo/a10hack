"""Serve the dashboard and bridge local operator requests to the managed harness."""

import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from demo import signin


FRONTEND = Path(__file__).resolve().parent
HARNESS = FRONTEND.parent / "trust_agent"
sys.path.insert(0, str(HARNESS))
import airlock
from sandbox.demo_agent import DEFAULT_REHEARSAL, REHEARSALS


SCENARIOS = [{"id": key, "title": case.title, "description": case.description} for key, case in REHEARSALS.items()]


class Operator:
    def __init__(self):
        self.lock = threading.Lock()
        self.audit_lock = threading.Lock()
        self.audit = {}
        self.starting = False
        self.start_error = ""
        self.stopping = set()
        self.stop_errors = {}

    def manifests(self):
        runs = []
        for path in airlock.RUNTIME.glob("*/run.json"):
            try:
                manifest = airlock.load(path.parent.name)
                created = path.with_name("compose.json").stat().st_mtime
            except (OSError, ValueError, KeyError):
                continue
            runs.append((created, manifest))
        return sorted(runs, key=lambda run: run[0], reverse=True)

    def events(self, manifest):
        session = manifest["session_id"]
        with self.audit_lock:
            cache = self.audit.setdefault(session, deque(maxlen=200))
            if manifest["status"] == "STOPPED":
                archive = Path(manifest["directory"]) / "audit.json"
                try:
                    return json.loads(archive.read_text())["events"][-200:]
                except (OSError, ValueError):
                    return list(cache)
            cursor = cache[-1]["seq"] if cache else 0
            while True:
                page = airlock.api(manifest, f"/events?after={cursor}")["events"]
                if not page:
                    break
                if page[-1]["seq"] <= cursor or any(event["session_id"] != session for event in page):
                    raise ValueError("Invalid audit stream")
                cache.extend(page)
                cursor = page[-1]["seq"]
                if len(page) < 1000:
                    break
            return list(cache)

    def snapshot(self, selected):
        manifests = self.manifests()
        if selected is None and manifests:
            selected = manifests[0][1]["session_id"]
        with self.lock:
            starting, start_error = self.starting, self.start_error
            stopping, stop_errors = self.stopping.copy(), self.stop_errors.copy()
        runs, current, events = [], None, []
        for created, manifest in manifests:
            session = manifest["session_id"]
            status = manifest["status"]
            case = REHEARSALS.get(manifest.get("rehearsal"))
            run = {"id": session, "status": status, "created": created, "stopError": stop_errors.get(session, ""),
                   "scenarioTitle": case.title if case else "Managed session"}
            if session == selected:
                if status in ("RUNNING", "STOPPED"):
                    try:
                        if status == "RUNNING":
                            guard = airlock.api(manifest, "/status")
                            if guard["session_id"] != session:
                                raise ValueError("Gateway session mismatch")
                            if guard["status"] == "KILLED":
                                run["status"] = "STOPPING"
                        events = self.events(manifest)
                    except (OSError, ValueError, KeyError):
                        run["status"] = "UNAVAILABLE"
                        with self.audit_lock:
                            events = list(self.audit.get(session, ()))
                current = run
            if status != "STOPPED" and session in stopping:
                run["status"] = "STOPPING"
            runs.append(run)
        return {"run": current, "runs": runs, "events": events, "starting": starting, "startError": start_error,
                "scenarios": SCENARIOS}

    def start(self, scenario):
        with self.lock:
            if self.starting:
                return False
            self.starting, self.start_error = True, ""
        threading.Thread(target=self.launch_rehearsal, args=(scenario,), daemon=True).start()
        return True

    def launch_rehearsal(self, scenario):
        try:
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            subprocess.run([
                sys.executable, str(HARNESS / "airlock.py"), "run",
                "--repo", str(HARNESS / "experiments/live_demo_repo"),
                "--port", str(port), "--detach", "--rehearsal", scenario,
            ], check=True, timeout=1500)
        except (OSError, subprocess.SubprocessError) as error:
            print(f"Managed rehearsal failed: {error}", file=sys.stderr, flush=True)
            with self.lock:
                self.start_error = "Could not launch the managed rehearsal. Check Docker and the dashboard server terminal."
        finally:
            with self.lock:
                self.starting = False

    def stop(self, session):
        manifest = airlock.load(session)
        with self.lock:
            if session in self.stopping or manifest["status"] == "STOPPED":
                return
            if manifest["status"] != "RUNNING":
                raise ValueError("The session is still being prepared")
            self.stopping.add(session)
            self.stop_errors.pop(session, None)
        threading.Thread(target=self.stop_run, args=(manifest,), daemon=True).start()

    def stop_run(self, manifest):
        session = manifest["session_id"]
        try:
            try:
                airlock.api(manifest, "/kill", {"session_id": session})
            except (OSError, ValueError):
                pass
            else:
                # Let the existing supervisor archive and verify container termination.
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    try:
                        if airlock.load(session)["status"] == "STOPPED":
                            return
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.25)
            airlock.stop(airlock.load(session))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"Managed stop failed for {session}: {error}", file=sys.stderr, flush=True)
            with self.lock:
                self.stop_errors[session] = "Could not verify that the run stopped. Check Docker and retry Stop."
        finally:
            with self.lock:
                self.stopping.discard(session)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND / "dist"), **kwargs)

    def local_host(self):
        try:
            host = urlsplit("//" + self.headers.get("Host", "")).hostname
        except ValueError:
            host = None
        return host in ("127.0.0.1", "localhost", "::1")

    def authorized(self):
        with signin.guard:
            name, expires = signin.sessions.get(signin.cookie(self, "ta_session"), (None, 0))
        return name == "Local operator" and expires > time.time()

    def do_GET(self):
        if not self.local_host():
            return signin.response(self, {"error": "Local dashboard only."}, 403)
        url = urlsplit(self.path)
        if url.path == "/auth/me":
            return signin.response(self, {"name": "Local operator" if self.authorized() else None, "providers": []})
        if url.path.startswith("/api/"):
            if not self.authorized():
                return signin.response(self, {"error": "Sign in with the local workspace code."}, 401)
            if url.path == "/api/state":
                session = parse_qs(url.query).get("session", [None])[0]
                snapshot = self.server.operator.snapshot(session)
                if session and snapshot["run"] is None:
                    return signin.response(self, {"error": "Managed session not found."}, 404)
                return signin.response(self, snapshot)
            return signin.response(self, {"error": "Unknown endpoint."}, 404)
        if url.path == "/":
            self.path = "/index.html"
        if self.path != "/index.html" and not self.path.startswith("/assets/"):
            return self.send_error(404)
        super().do_GET()

    def do_POST(self):
        if not self.local_host() or self.headers.get("X-Airlock-Demo") != "1":
            return signin.response(self, {"error": "Local dashboard request required."}, 403)
        if self.path in ("/auth/local", "/auth/logout"):
            try:
                return signin.handle(self)
            except ValueError:
                return signin.response(self, {"error": "Invalid sign-in request."}, 400)
        if not self.authorized():
            return signin.response(self, {"error": "Sign in with the local workspace code."}, 401)
        if self.path == "/api/start":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 1024:
                    raise ValueError("Invalid request length")
                payload = json.loads(self.rfile.read(length)) if length else {"scenario": DEFAULT_REHEARSAL}
                if not isinstance(payload, dict) or not isinstance(payload.get("scenario"), str):
                    raise ValueError("Expected a scenario ID")
                scenario = payload["scenario"]
                if scenario not in REHEARSALS:
                    raise ValueError("Unknown scenario")
            except (ValueError, UnicodeError):
                return signin.response(self, {"error": "Choose a supported rehearsal scenario."}, 400)
            if not self.server.operator.start(scenario):
                return signin.response(self, {"error": "A rehearsal is already starting."}, 409)
        elif self.path.startswith("/api/runs/") and self.path.endswith("/stop"):
            session = self.path.removeprefix("/api/runs/").removesuffix("/stop")
            try:
                self.server.operator.stop(session)
            except FileNotFoundError:
                return signin.response(self, {"error": "Managed session not found."}, 404)
            except ValueError:
                return signin.response(self, {"error": "The selected session cannot be stopped yet."}, 409)
        else:
            return signin.response(self, {"error": "Unknown endpoint."}, 404)
        signin.response(self, {"ok": True}, 202)

    def list_directory(self, path):
        self.send_error(404)
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8798)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.operator = Operator()
        print("Local workspace sign-in code:", signin.code, flush=True)
        print(f"TrustAgent dashboard: http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
