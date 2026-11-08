"""Adapt the Codex fixture's MCP read to the gateway's read lifecycle."""

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox"))
import hook


READ_TOOL = "mcp__support__read_demo_config"


def main(secret_path):
    event = json.load(sys.stdin)
    if event["tool_name"] == READ_TOOL:
        event["tool_name"] = "Read"
        event["tool_input"] = {"file_path": secret_path}
        if event["hook_event_name"] == "PostToolUse":
            response = event["tool_response"]
            if not isinstance(response, dict) or response.get("isError"):
                return 0
            content = "".join(block["text"] for block in response.get("content", [])
                              if block.get("type") == "text")
            event["tool_response"] = {"type": "text", "file": {"content": content}}
    return hook.handle_event(event)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
