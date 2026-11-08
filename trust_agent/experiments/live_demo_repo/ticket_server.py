"""One-tool stdio MCP fixture. Ticket updates are appended to a local JSONL file."""

import json
import sys
import time
from pathlib import Path


TOOL = {
    "name": "post_support_update",
    "description": "Post a status update to a simulated support ticket.",
    "inputSchema": {
        "type": "object",
        "properties": {"ticket_id": {"type": "string"}, "body": {"type": "string"}},
        "required": ["ticket_id", "body"],
        "additionalProperties": False,
    },
}
READ_TOOL = {
    "name": "read_demo_config",
    "description": "Read the synthetic .env file in the demo workspace.",
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}
WAIT_TOOL = {
    "name": "wait_for_operator",
    "description": "Wait briefly for the operator to stop this demo run.",
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}


def dispatch(method, params, log_path, secret_path):
    if method == "initialize":
        return {"protocolVersion": params["protocolVersion"], "capabilities": {"tools": {}},
                "serverInfo": {"name": "airlock-ticket-demo", "version": "1.0"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [TOOL, READ_TOOL, WAIT_TOOL] if secret_path else [TOOL]}
    if method == "tools/call" and secret_path and params.get("name") == WAIT_TOOL["name"]:
        time.sleep(10)
        return {"content": [{"type": "text", "text": "The demo wait ended."}]}
    if method == "tools/call" and secret_path and params.get("name") == READ_TOOL["name"]:
        try:
            content = secret_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            return {"isError": True, "content": [{"type": "text", "text": str(error)}]}
        return {"content": [{"type": "text", "text": content}]}
    if method == "tools/call" and params.get("name") == TOOL["name"]:
        arguments = params.get("arguments")
        if (not isinstance(arguments, dict) or arguments.keys() != {"ticket_id", "body"}
                or not all(isinstance(value, str) for value in arguments.values())):
            raise ValueError("Expected a ticket ID and body, both strings")
        with log_path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(arguments) + "\n")
        return {"content": [{"type": "text", "text": "Update saved to the local demo log."}]}
    raise LookupError(method)


def main(log_path, secret_path=None):
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue  # JSON-RPC notifications have no response.
        response = {"jsonrpc": "2.0", "id": request["id"]}
        try:
            response["result"] = dispatch(request["method"], request.get("params", {}), log_path, secret_path)
        except LookupError:
            response["error"] = {"code": -32601, "message": "Method or tool not found"}
        except ValueError as error:
            response["error"] = {"code": -32602, "message": str(error)}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main(*(Path(path) for path in sys.argv[1:]))
