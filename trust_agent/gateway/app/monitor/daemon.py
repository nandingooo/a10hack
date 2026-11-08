"""AgentAirlock full-activity monitor daemon.

Standalone: tails every live Claude Code session transcript, turns each tool
call into a provenance ContextEntry via the labeler, records it in the
QueueStore, and surfaces a labeled live view + per-session risk. Observe-only
(the hook/sensor is the blocking path); this is the "see everything" layer.

Run:
  python gateway/app/monitor/daemon.py              # tail ~/.claude/projects live
  python gateway/app/monitor/daemon.py --once       # single pass (demo/CI)
  python gateway/app/monitor/daemon.py --projects-dir <dir> --active-within 3600
"""
from __future__ import annotations

import os
import sys
import time
from typing import Callable, Optional

# Make the provenance package + this package importable whether run as a script
# or imported as a module.
_APP = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _APP not in sys.path:
    sys.path.insert(0, _APP)

from provenance import (  # noqa: E402
    ActionProps, Channel, ContextEntry, GraphStore, Kind, Labeler, Op, Policy,
    ProvenanceStore, QueueStore, Sensitivity, new_entry_id,
)
from monitor.discovery import default_projects_dir, find_transcripts  # noqa: E402
from monitor.normalize import Activity, normalize_line  # noqa: E402
from monitor.tailer import JsonlTailer  # noqa: E402

_OP = {
    "ReadFile": Op.READ_FILE, "WriteFile": Op.WRITE_FILE, "RunCommand": Op.RUN_COMMAND,
    "NetworkRequest": Op.NETWORK_REQUEST, "CallTool": Op.CALL_TOOL,
}
_UNTRUSTED_MARKERS = ("/vendor/", "/external/", "/node_modules/", "/.cache/", "/site-packages/")
_DESTRUCTIVE = ("rm -rf", "rm -r ", "git push --force", "git push -f", "drop table", "mkfs", "sudo ")

EventCallback = Callable[[ContextEntry, Optional[object]], None]


def default_policy() -> Policy:
    return Policy.load()


def resolve_origin(op: str, target: str) -> str:
    """Sensor-side step: decide an activity's origin (the trust input)."""
    if op == "NetworkRequest":
        return "web"
    if op == "CallTool":
        return "tool-output"
    t = target.replace("\\", "/").lower()
    if any(m in t for m in _UNTRUSTED_MARKERS):
        return "cloned-repo"
    return default_policy().origin(t)


def _is_destructive(cmd: str) -> bool:
    c = cmd.lower()
    return any(p in c for p in _DESTRUCTIVE)


class Monitor:
    def __init__(
        self,
        projects_dir: Optional[str] = None,
        poll_s: float = 1.0,
        active_within_s: Optional[float] = None,
        on_event: Optional[EventCallback] = None,
        policy: Optional[Policy] = None,
        store: Optional[ProvenanceStore] = None,
    ) -> None:
        self.projects_dir = projects_dir or default_projects_dir()
        self.poll_s = poll_s
        self.active_within_s = active_within_s
        self.labeler = Labeler(policy or default_policy())
        self.store: ProvenanceStore = store if store is not None else QueueStore()
        self.on_event: EventCallback = on_event or self._print_event
        self._tailers: dict[str, JsonlTailer] = {}
        self._seq = 0

    def poll_once(self) -> None:
        for path in find_transcripts(self.projects_dir, self.active_within_s):
            tailer = self._tailers.get(path)
            if tailer is None:
                tailer = JsonlTailer(path)
                self._tailers[path] = tailer
            for line in tailer.read_new():
                for act in normalize_line(line):
                    self._ingest(act)

    def _ingest(self, act: Activity) -> None:
        origin = resolve_origin(act.op, act.target)
        labels = self.labeler.label(act.target, origin)
        is_action = act.kind == "action"
        if not is_action and labels.sensitivity == Sensitivity.SECRET:
            kind = Kind.SECRET
        elif is_action:
            kind = Kind.ACTION
        else:
            kind = Kind.SOURCE

        action_props = None
        if is_action:
            is_exit = act.op == "NetworkRequest" and not self.labeler.approved_host(act.target)
            destructive = act.op == "RunCommand" and _is_destructive(act.target)
            action_props = ActionProps(is_exit=is_exit, is_destructive=destructive)

        self._seq += 1
        entry = ContextEntry(
            id=new_entry_id(act.session_id or "unknown", self._seq),
            ts=act.ts, session_id=act.session_id or "unknown", kind=kind,
            channel=Channel.HOOK,  # the monitor observes the same events a hook would
            op=_OP[act.op], target=act.target, origin=origin, labels=labels,
            action_props=action_props,
        )
        self.store.append(entry)
        agg = self.store.aggregate(entry.session_id, entry) if is_action else None
        self.on_event(entry, agg)

    def _print_event(self, entry: ContextEntry, agg: object) -> None:
        sid = entry.session_id[:8]
        print(f"[{sid}] {entry.op.value:14s} "
              f"trust={entry.labels.effective_trust.value:9s} "
              f"sens={entry.labels.sensitivity.value:9s} "
              f"bait={str(entry.labels.bait):5s} {entry.target}")
        a = agg
        if a is not None and (a.reached_untrusted or a.reached_secret or a.reached_bait):  # type: ignore[attr-defined]
            print(f"     -> session risk: untrusted={a.reached_untrusted} "  # type: ignore[attr-defined]
                  f"secret={a.reached_secret} bait={a.reached_bait}")        # type: ignore[attr-defined]

    def run(self) -> None:
        while True:
            self.poll_once()
            time.sleep(self.poll_s)


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="AgentAirlock full-activity monitor")
    ap.add_argument("--projects-dir", default=None, help="Claude projects dir (default ~/.claude/projects)")
    ap.add_argument("--once", action="store_true", help="single pass then exit")
    ap.add_argument("--poll", type=float, default=1.0, help="poll interval seconds")
    ap.add_argument("--active-within", type=float, default=None,
                    help="only tail transcripts modified within N seconds")
    ap.add_argument("--store", choices=["queue", "graph"], default="queue",
                    help="provenance store: queue (session union) or graph (trace_back)")
    a = ap.parse_args(argv)
    store = GraphStore() if a.store == "graph" else QueueStore()
    mon = Monitor(projects_dir=a.projects_dir, poll_s=a.poll,
                  active_within_s=a.active_within, store=store)
    if a.once:
        mon.poll_once()
        return 0
    print(f"AgentAirlock monitor: tailing {mon.projects_dir} (Ctrl+C to stop)")
    try:
        mon.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
