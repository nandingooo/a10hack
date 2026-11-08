"""Find Claude Code session transcripts to tail (stdlib only).

Claude Code stores transcripts under ``~/.claude/projects/<slug>/<id>.jsonl``.
We enumerate those files; optionally only ones modified recently (live sessions).
"""
from __future__ import annotations

import os
import time
from pathlib import Path


def default_projects_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".claude", "projects")


def find_transcripts(projects_dir: str, active_within_s: float | None = None) -> list[str]:
    root = Path(projects_dir)
    if not root.is_dir():
        return []
    now = time.time()
    out: list[str] = []
    for p in root.rglob("*.jsonl"):
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if active_within_s is not None and (now - mtime) > active_within_s:
            continue
        out.append(str(p))
    return sorted(out)
