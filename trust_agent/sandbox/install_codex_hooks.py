"""Install the TrustAgent sensor into OpenAI Codex's hook config.

Codex reads ``~/.codex/hooks.json`` (global) with the SAME hook wire format as
Claude Code: ``{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [...]}]}}``.
We reuse the one agent-neutral sensor (``hook.py``) and register it for the two
blocking/completion events Codex fires (``PreToolUse`` + ``PostToolUse``), so a
Codex session is routed through the same gateway as Claude Code.

This MERGES: any existing hooks (e.g. the user's ``impeccable`` design hook) are
preserved; only a prior TrustAgent entry (matched by the hook.py path) is
replaced, so re-running is idempotent.

Usage:
  python install_codex_hooks.py            # global  ~/.codex/hooks.json
  python install_codex_hooks.py --config C:/path/to/hooks.json
  python install_codex_hooks.py --uninstall
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Codex fires these two around a tool call; hook.py handles both phases.
EVENTS = ("PreToolUse", "PostToolUse")


def _default_config() -> Path:
    return Path.home() / ".codex" / "hooks.json"


def _definition(script: Path) -> dict:
    """One hook group that invokes the shared sensor. ``command`` is the POSIX
    form; ``commandWindows`` is evaluated by PowerShell, which needs its call
    operator before a quoted executable path."""
    exe = sys.executable
    invoke = f'"{exe}" "{script.as_posix()}" --agent codex'
    return {
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": invoke,
            "commandWindows": f'& "{exe}" "{script}" --agent codex',
            "timeout": 10,
            "statusMessage": "TrustAgent guard",
        }],
    }


def _strip_ours(groups: list, script: Path) -> list:
    """Drop any prior TrustAgent entry (identified by the hook.py path), keeping
    every unrelated hook group intact."""
    needle = script.as_posix().casefold()
    kept = []
    for group in groups:
        hooks = [h for h in group.get("hooks", [])
                 if needle not in (h.get("command", "") + h.get("commandWindows", "")).replace("\\", "/").casefold()]
        if hooks:
            kept.append({**group, "hooks": hooks})
    return kept


def install(config: Path, uninstall: bool = False) -> Path:
    script = Path(__file__).with_name("hook.py").resolve()
    data = json.loads(config.read_text(encoding="utf-8")) if config.exists() else {}
    if not isinstance(data, dict):
        data = {}
    hooks = data.setdefault("hooks", {})
    for event in EVENTS:
        groups = _strip_ours(hooks.get(event, []), script)
        if not uninstall:
            groups.append(_definition(script))
        if groups:
            hooks[event] = groups
        else:
            hooks.pop(event, None)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, default=_default_config(),
                        help="path to Codex hooks.json (default: ~/.codex/hooks.json)")
    parser.add_argument("--uninstall", action="store_true",
                        help="remove the TrustAgent hook, preserving other hooks")
    args = parser.parse_args()
    path = install(args.config, args.uninstall)
    print(("uninstalled from " if args.uninstall else "installed into ") + str(path))
