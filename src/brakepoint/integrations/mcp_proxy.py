"""Stdio MCP proxy: sits between any MCP client and any stdio MCP server.

    client  <->  brakepoint mcp-proxy --name gmail -- npx some-mcp-server  <->  server

Every `tools/call` request is evaluated before it reaches the server. Calls
that need approval go to the configured approver (terminal or queue); denied
calls get a tool error back, so the model sees why and the server never sees
the call.

The proxy also reads the server's `tools/list` response. If the server marks a
tool with the MCP `destructiveHint` annotation, Brakepoint treats it as at
least high severity. Server hints are only ever used to tighten, never to
relax: a server that marks a dangerous tool as read-only gains nothing.

A client may call a tool without listing first, or send the call before the
server's `tools/list` reply has come back. So before evaluating a call, the
proxy makes sure it has seen the server's complete tool list, fetching it
itself if needed. If it cannot get the list, the call is blocked.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import threading
from typing import IO

from ..actions import Action
from ..approval import build_approver
from ..audit import AuditLog
from ..catalog import Rule
from ..engine import Engine, Match
from ..policy import Policy

HINT_RULE = Rule(
    id="BP-HINT-001",
    title="Tool declared destructive by its MCP server",
    category="data-destruction",
    platform="mcp",
    severity="high",
    reversibility="irreversible",
    kinds=("tool",),
    patterns=(re.compile(r".^"),),  # never matches text; added from annotations
    why="The server itself flags this tool as destructive (MCP destructiveHint).",
    safer="Approve each call, or remove the tool from the agent.",
    source="mcp-annotations",
)


class McpProxy:
    list_timeout = 10.0  # seconds to wait for the server's tools/list reply
    list_max_pages = 100

    def __init__(
        self,
        server_cmd: list[str],
        name: str,
        policy: Policy,
        client_in: IO[bytes] | None = None,
        client_out: IO[bytes] | None = None,
    ):
        self.server_cmd = server_cmd
        self.name = name
        self.policy = policy
        self.engine = Engine(policy)
        self.approver = build_approver(policy)
        self.audit = AuditLog(policy.audit_path, policy.audit_enabled)
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._list_ids: dict = {}  # client tools/list id -> whether it asked for a later page
        self.destructive_tools: set[str] = set()
        self.tools_known = False  # set once a complete tool list has been seen
        self._own_requests: dict[str, tuple[threading.Event, list]] = {}
        self._own_counter = 0
        self._own_prefix = secrets.token_hex(4)  # so a client's own ids cannot collide
        self._server_closed = threading.Event()
        self.proc: subprocess.Popen | None = None

    # ----------------------------------------------------------- plumbing
    def _send_client(self, message: dict | bytes) -> None:
        data = message if isinstance(message, bytes) else (json.dumps(message) + "\n").encode()
        with self._out_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def _send_server(self, line: bytes) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _pump_server(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            for line in iter(self.proc.stdout.readline, b""):
                if self._observe_server(line):
                    continue  # reply to the proxy's own request; the client never asked for it
                self._send_client(line)
        finally:
            self._server_closed.set()
            for event, _ in list(self._own_requests.values()):
                event.set()

    def _observe_server(self, line: bytes) -> bool:
        """Learn from a server message. Return True if it answers the proxy's own request."""
        try:
            msg = json.loads(line)
        except ValueError:
            return False
        if not isinstance(msg, dict):
            return False
        if msg.get("method") == "notifications/tools/list_changed":
            self.tools_known = False
            return False
        msg_id = msg.get("id")
        if isinstance(msg_id, str) and msg_id in self._own_requests:
            event, slot = self._own_requests[msg_id]
            slot.append(msg)
            event.set()
            return True
        if msg_id is None or msg_id not in self._list_ids:
            return False
        was_continuation = self._list_ids.pop(msg_id)
        result = msg.get("result") or {}
        self._learn_tools(result)
        if not was_continuation and not result.get("nextCursor") and "error" not in msg:
            self.tools_known = True
        return False

    def _learn_tools(self, result: dict) -> None:
        for tool in result.get("tools", []) or []:
            annotations = tool.get("annotations") or {}
            if annotations.get("destructiveHint") is True:
                self.destructive_tools.add(tool.get("name", ""))

    def _server_request(self, method: str, params: dict, timeout: float) -> dict:
        """Send a request of the proxy's own to the server and wait for the reply."""
        self._own_counter += 1
        request_id = f"brakepoint-{self._own_prefix}-{self._own_counter}"
        event, slot = threading.Event(), []
        self._own_requests[request_id] = (event, slot)
        try:
            self._send_server(
                (json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n").encode()
            )
            if not event.wait(timeout) or not slot:
                raise RuntimeError(f"no reply from the MCP server to {method}")
            reply = slot[0]
            if "error" in reply:
                raise RuntimeError(f"the MCP server refused {method}: {reply['error']}")
            return reply.get("result") or {}
        finally:
            self._own_requests.pop(request_id, None)

    def ensure_tools_known(self) -> None:
        """Fetch the server's complete tool list unless it has been seen already."""
        if self.tools_known:
            return
        if self.proc is None or self._server_closed.is_set():
            raise RuntimeError("the MCP server is not running, so its tool annotations are unknown")
        cursor = None
        for _ in range(self.list_max_pages):
            result = self._server_request("tools/list", {"cursor": cursor} if cursor else {}, self.list_timeout)
            self._learn_tools(result)
            cursor = result.get("nextCursor")
            if not cursor:
                self.tools_known = True
                return
        raise RuntimeError("the MCP server's tool list has too many pages")

    # ----------------------------------------------------------- policy
    def check_call(self, msg: dict) -> dict | None:
        """Return an error response for the client, or None to forward."""
        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}
        self.ensure_tools_known()
        action = Action.tool(f"mcp__{self.name}__{tool}", args, origin=f"mcp-proxy:{self.name}")
        extra = []
        if tool in self.destructive_tools:
            decision, note = self.engine.decide(HINT_RULE, protected=False)
            extra.append(Match(HINT_RULE, tool, False, decision, note or "server annotation"))
        verdict = self.engine.evaluate(action, extra_matches=extra)
        context = {"harness": "mcp-proxy", "server": self.name}

        if verdict.decision == "allow":
            return None
        if verdict.decision == "log":
            self.audit.record(verdict, "allowed", extra=context)
            return None
        if verdict.decision == "approve":
            result = self.approver.request(verdict)
            self.audit.record(
                verdict, "approved" if result.approved else "rejected", approver=result.approver, extra=context
            )
            if result.approved:
                return None
            reason = verdict.reason("agent") + f"\nA human did not approve this call ({result.detail})."
        else:
            self.audit.record(verdict, "blocked", extra=context)
            reason = verdict.reason("agent")
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {"content": [{"type": "text", "text": reason}], "isError": True},
        }

    # ----------------------------------------------------------- main loop
    def run(self) -> int:
        self.proc = subprocess.Popen(self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        pump = threading.Thread(target=self._pump_server, daemon=True)
        pump.start()
        try:
            for line in iter(self.client_in.readline, b""):
                try:
                    msg = json.loads(line)
                except ValueError:
                    self._send_server(line)
                    continue
                if isinstance(msg, dict) and msg.get("method") == "tools/list" and msg.get("id") is not None:
                    self._list_ids[msg.get("id")] = bool((msg.get("params") or {}).get("cursor"))
                if isinstance(msg, dict) and msg.get("method") == "tools/call":
                    try:
                        blocked = self.check_call(msg)
                    except Exception as exc:  # fail closed
                        blocked = {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "result": {
                                "content": [{"type": "text", "text": f"Brakepoint error, call blocked: {exc}"}],
                                "isError": True,
                            },
                        }
                    if blocked is not None:
                        self._send_client(blocked)
                        continue
                self._send_server(line)
        finally:
            if self.proc.stdin:
                self.proc.stdin.close()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
            pump.join(timeout=2)
        return self.proc.returncode or 0
