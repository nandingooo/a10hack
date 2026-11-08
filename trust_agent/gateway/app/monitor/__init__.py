"""AgentAirlock full-activity monitor: tails Claude Code transcripts and labels
every tool call via the provenance module. Standalone; observe-only."""
from .tailer import JsonlTailer
from .normalize import Activity, normalize_line
from .discovery import default_projects_dir, find_transcripts
from .daemon import Monitor, default_policy, resolve_origin

__all__ = [
    "JsonlTailer", "Activity", "normalize_line",
    "default_projects_dir", "find_transcripts",
    "Monitor", "default_policy", "resolve_origin",
]
