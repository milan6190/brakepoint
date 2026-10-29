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
"""

from __future__ import annotations

import json
import re
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
        self._list_ids: set = set()
        self.destructive_tools: set[str] = set()
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
        for line in iter(self.proc.stdout.readline, b""):
            self._observe_server(line)
            self._send_client(line)

    def _observe_server(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            return
        if not isinstance(msg, dict) or msg.get("id") not in self._list_ids:
            return
        self._list_ids.discard(msg.get("id"))
        for tool in (msg.get("result") or {}).get("tools", []) or []:
            annotations = tool.get("annotations") or {}
            if annotations.get("destructiveHint") is True:
                self.destructive_tools.add(tool.get("name", ""))

    # ----------------------------------------------------------- policy
    def check_call(self, msg: dict) -> dict | None:
        """Return an error response for the client, or None to forward."""
        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}
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
                if isinstance(msg, dict) and msg.get("method") == "tools/list":
                    self._list_ids.add(msg.get("id"))
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
