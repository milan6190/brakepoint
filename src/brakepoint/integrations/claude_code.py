"""Claude Code PreToolUse hook.

Claude Code sends the pending tool call as JSON on stdin. Brakepoint answers:

* nothing (exit 0, no output) when the action is fine, so Claude Code's own
  permission rules still apply. Brakepoint only ever tightens, never loosens.
* "ask" when a human should approve. Claude Code shows its own permission
  prompt, which the model cannot answer.
* "deny" with the reason and a safer alternative, which is sent back to the
  model so it can change course.

If anything goes wrong inside Brakepoint, the hook exits 2, which blocks the
call (fail closed).
"""

from __future__ import annotations

import json
import sys
import traceback

from ..actions import Action
from ..audit import AuditLog
from ..engine import Engine
from ..policy import Policy

FILE_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
FILE_READ_TOOLS = {"Read"}
URL_TOOLS = {"WebFetch"}


def action_from_hook(payload: dict) -> Action | None:
    tool = payload.get("tool_name", "")
    data = payload.get("tool_input") or {}
    if tool == "Bash":
        return Action.shell(str(data.get("command", "")), origin="claude-code")
    if tool in FILE_WRITE_TOOLS:
        path = data.get("file_path") or data.get("notebook_path") or ""
        return Action.file(str(path), "write", origin="claude-code")
    if tool in FILE_READ_TOOLS:
        return Action.file(str(data.get("file_path", "")), "read", origin="claude-code")
    if tool in URL_TOOLS:
        return Action.url(str(data.get("url", "")), origin="claude-code")
    if tool.startswith("mcp__"):
        return Action.tool(tool, data, origin="claude-code")
    return None


def hook_response(decision: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def handle(payload: dict, policy: Policy, engine: Engine | None = None) -> dict | None:
    """Return the hook JSON to print, or None for 'no opinion'."""
    action = action_from_hook(payload)
    if action is None:
        return None
    engine = engine or Engine(policy)
    verdict = engine.evaluate(action)
    audit = AuditLog(policy.audit_path, policy.audit_enabled)
    context = {
        "harness": "claude-code",
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "permission_mode": payload.get("permission_mode"),
        "tool_use_id": payload.get("tool_use_id"),
    }

    if verdict.decision in ("allow", "log"):
        if verdict.decision == "log":
            audit.record(verdict, "allowed", extra=context)
        return None

    if verdict.decision == "approve":
        mode = payload.get("permission_mode", "default")
        if mode in policy.unattended_modes or policy.approval_backend == "deny":
            verdict.decision = "deny"
            audit.record(verdict, "blocked", approver=f"unattended:{mode}", extra=context)
            reason = verdict.reason("agent") + f"\nNo human is available to approve in '{mode}' mode."
            return hook_response("deny", reason)
        audit.record(verdict, "asked", approver="claude-code-prompt", extra=context)
        return hook_response("ask", verdict.reason("human"))

    audit.record(verdict, "blocked", extra=context)
    return hook_response("deny", verdict.reason("agent"))


def main(stdin=None, stdout=None, policy_path: str | None = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        payload = json.load(stdin)
        policy = Policy.load(policy_path, start=payload.get("cwd"))
        response = handle(payload, policy)
    except Exception as exc:  # fail closed
        sys.stderr.write(
            f"Brakepoint could not evaluate this action and blocked it to be safe: {exc}\n"
            + traceback.format_exc(limit=2)
        )
        return 2
    if response is not None:
        stdout.write(json.dumps(response))
        stdout.flush()
    return 0
