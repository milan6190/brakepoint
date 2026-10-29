"""Claude Code hook, MCP proxy, audit log, redaction, and CLI."""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from brakepoint import Policy
from brakepoint.audit import AuditLog
from brakepoint.cli import main as cli_main
from brakepoint.integrations import claude_code
from brakepoint.integrations.mcp_proxy import McpProxy
from brakepoint.redact import redact

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def policy(tmp_path):
    return Policy.from_dict({"audit": {"path": str(tmp_path / "audit.jsonl")}, "approval": {"backend": "deny"}})


@pytest.fixture
def asking_policy(tmp_path):
    return Policy.from_dict({"audit": {"path": str(tmp_path / "audit.jsonl")}})


def hook(payload, policy):
    return claude_code.handle(payload, policy)


# ------------------------------------------------------------------ Claude Code
def test_hook_stays_silent_for_safe_commands(asking_policy):
    assert hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}, asking_policy) is None


def test_hook_asks_human_for_destructive_command(asking_policy):
    out = hook(
        {"tool_name": "Bash", "tool_input": {"command": "terraform destroy"}, "permission_mode": "default"},
        asking_policy,
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "BP-IAC-001" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_hook_denies_when_nobody_can_answer(asking_policy):
    out = hook(
        {"tool_name": "Bash", "tool_input": {"command": "terraform destroy"}, "permission_mode": "bypassPermissions"},
        asking_policy,
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_denies_production_wipe_and_tells_agent_not_to_retry(asking_policy):
    out = hook({"tool_name": "Bash", "tool_input": {"command": "kubectl delete ns prod"}}, asking_policy)
    decision = out["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "Do not retry" in decision["permissionDecisionReason"]


def test_hook_blocks_settings_tampering(asking_policy):
    out = hook({"tool_name": "Edit", "tool_input": {"file_path": "/repo/.claude/settings.json"}}, asking_policy)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_checks_mcp_tools(asking_policy):
    out = hook({"tool_name": "mcp__gmail__batchDelete", "tool_input": {"query": "in:inbox"}}, asking_policy)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_ignores_unrelated_tools(asking_policy):
    assert hook({"tool_name": "Glob", "tool_input": {"pattern": "*"}}, asking_policy) is None


def test_hook_fails_closed_on_bad_input(capsys):
    code = claude_code.main(stdin=io.StringIO("not json"), stdout=io.StringIO())
    assert code == 2


def test_hook_writes_audit_entries(asking_policy):
    hook({"tool_name": "Bash", "tool_input": {"command": "terraform destroy"}}, asking_policy)
    log = AuditLog(asking_policy.audit_path)
    entries = [json.loads(line) for _, line in log.entries()]
    assert entries and entries[-1]["outcome"] == "asked"


# ------------------------------------------------------------------ audit + redaction
def test_audit_chain_detects_tampering(asking_policy):
    for command in ("terraform destroy", "kubectl delete ns prod", "git push -f"):
        hook({"tool_name": "Bash", "tool_input": {"command": command}}, asking_policy)
    log = AuditLog(asking_policy.audit_path)
    assert log.verify()[0]
    path = Path(asking_policy.audit_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")  # delete the middle entry
    ok, message = log.verify()
    assert not ok and "line 2" in message


def test_secrets_are_redacted_in_audit(asking_policy):
    hook(
        {
            "tool_name": "Bash",
            "tool_input": {
                "command": "curl -X DELETE -H 'Authorization: Bearer abcdefghijklmnop1234' https://api.x/v1/a"
            },
        },
        asking_policy,
    )
    text = Path(asking_policy.audit_path).read_text()
    assert "abcdefghijklmnop1234" not in text


# Fake tokens are assembled at runtime so secret scanners (including GitHub
# push protection) don't flag the test file as containing real credentials.
@pytest.mark.parametrize(
    "prefix,body",
    [
        ("AK" + "IA", "ABCDEFGHIJKLMNOP"),
        ("gh" + "p_", "abcdefghijklmnopqrstuvwxyz0123"),
        ("da" + "pi", "0123456789abcdef" * 2),
        ("sk" + "-ant-", "abcdefghijklmnopqrstuvwxyz"),
    ],
)
def test_redact_known_token_formats(prefix, body):
    secret = prefix + body
    assert secret not in redact(f"export X={secret} && run")


def test_redact_connection_string_password():
    assert "hunter22" not in redact("psql postgres://admin:hunter22@db:5432/app")


def test_redact_leaves_ordinary_flags_alone():
    assert redact("mkdir -p build") == "mkdir -p build"


# ------------------------------------------------------------------ MCP proxy
def _run_proxy(messages, policy):
    client_in = io.BytesIO(b"".join((json.dumps(m) + "\n").encode() for m in messages))
    client_out = io.BytesIO()
    proxy = McpProxy([sys.executable, str(FIXTURES / "fake_mcp_server.py")], "mail", policy, client_in, client_out)
    proxy.run()
    return [json.loads(line) for line in client_out.getvalue().splitlines()], proxy


def test_mcp_proxy_forwards_safe_calls_and_blocks_destructive_ones(policy):
    replies, _ = _run_proxy(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_messages", "arguments": {}}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "batch_delete", "arguments": {"all": True}},
            },
        ],
        policy,
    )
    by_id = {r["id"]: r for r in replies}
    assert by_id[2]["result"]["content"][0]["text"] == "server ran list_messages"
    assert by_id[3]["result"]["isError"] is True
    assert "BP-TOOL-001" in by_id[3]["result"]["content"][0]["text"]


def test_mcp_proxy_honours_destructive_hint(policy):
    # archive_thread is not caught by name, but the server declares it destructive.
    _, proxy = _run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}], policy)
    assert "archive_thread" in proxy.destructive_tools
    blocked = proxy.check_call({"id": 9, "params": {"name": "archive_thread", "arguments": {}}})
    assert blocked is not None and "BP-HINT-001" in blocked["result"]["content"][0]["text"]


# ------------------------------------------------------------------ CLI
def test_cli_check_exit_codes(capsys):
    assert cli_main(["check", "ls"]) == 0
    assert cli_main(["check", "terraform", "destroy"]) == 3
    assert cli_main(["check", "brakepoint", "approve", "x"]) == 4


def test_cli_replay_stops_every_incident():
    assert cli_main(["replay"]) == 0


def test_cli_exec_runs_safe_commands_and_blocks_locked_ones():
    def run(*cmd):
        return subprocess.run(
            [sys.executable, "-m", "brakepoint", "exec", "--", *cmd],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    result = run("echo", "hello")
    assert result.returncode == 0 and "hello" in result.stdout
    blocked = run("brakepoint approve abc")
    assert blocked.returncode == 4 and "BP-SELF-001" in blocked.stderr


def test_cli_catalog_markdown(capsys):
    assert cli_main(["catalog", "--markdown"]) == 0
    assert "| `BP-SQL-001` |" in capsys.readouterr().out


# ------------------------------------------------------------------ approval queue
def test_queue_approval_round_trip(tmp_path):
    import threading
    import time

    from brakepoint import Action, Engine
    from brakepoint.approval import QueueApprover

    approver = QueueApprover(tmp_path / "queue", timeout=5, poll=0.05)
    verdict = Engine().evaluate(Action.shell("terraform destroy"))

    def human():
        for _ in range(100):
            pending = approver.pending()
            if pending:
                approver.decide(pending[0]["id"], approve=True)
                return
            time.sleep(0.05)

    threading.Thread(target=human).start()
    result = approver.request(verdict)
    assert result.approved
    assert approver.pending() == []


def test_queue_times_out_closed(tmp_path):
    from brakepoint import Action, Engine
    from brakepoint.approval import QueueApprover

    approver = QueueApprover(tmp_path / "queue", timeout=0.2, poll=0.05)
    result = approver.request(Engine().evaluate(Action.shell("terraform destroy")))
    assert not result.approved
