"""A minimal stdio MCP server used by the proxy tests."""

import json
import sys

TOOLS = [
    {"name": "list_messages", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
    {"name": "archive_thread", "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": True}},
    {"name": "batch_delete", "inputSchema": {"type": "object"}},
]

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "0"},
        }
    elif msg["method"] == "tools/list":
        result = {"tools": TOOLS}
    elif msg["method"] == "tools/call":
        result = {"content": [{"type": "text", "text": "server ran " + msg["params"]["name"]}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
