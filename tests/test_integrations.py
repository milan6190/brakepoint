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


# ------------------------------------------------------------------ regressions
def test_hook_checks_grep_on_secrets_files(asking_policy):
    out = hook({"tool_name": "Grep", "tool_input": {"pattern": ".", "path": "/home/u/.aws/credentials"}}, asking_policy)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    out = hook({"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": ".", "glob": "**/.env"}}, asking_policy)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert hook({"tool_name": "Grep", "tool_input": {"pattern": "def ", "path": "src"}}, asking_policy) is None


@pytest.mark.parametrize(
    "path", [".claude//settings.json", "/repo/.claude/./settings.json", ".claude/x/../settings.json"]
)
def test_hook_normalises_paths_before_self_protection(asking_policy, path):
    out = hook({"tool_name": "Write", "tool_input": {"file_path": path, "content": "{}"}}, asking_policy)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_reads_policy_from_project_dir_not_cwd(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".brakepoint.yaml").write_text(
        f"defaults: {{high: deny}}\naudit: {{path: {tmp_path / 'audit.jsonl'}}}\n"
    )
    monkeypatch.delenv("BRAKEPOINT_POLICY", raising=False)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    payload = {"tool_name": "Bash", "tool_input": {"command": "git push --force"}, "cwd": str(tmp_path)}
    out = io.StringIO()
    assert claude_code.main(stdin=io.StringIO(json.dumps(payload)), stdout=out) == 0
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_audit_chain_survives_entries_larger_than_the_read_block(asking_policy, tmp_path):
    from brakepoint import Action, Engine

    log = AuditLog(tmp_path / "big.jsonl")
    engine = Engine(asking_policy)
    log.record(engine.evaluate(Action.shell("sudo echo " + "x" * 300_000)), "allowed")
    log.record(engine.evaluate(Action.shell("sudo ls")), "allowed")
    log.record(engine.evaluate(Action.shell("sudo echo " + "y" * 70_000)), "allowed")
    log.record(engine.evaluate(Action.shell("sudo ls")), "allowed")
    assert log.verify() == (True, "4 entries, chain intact")


def test_mcp_proxy_refuses_batched_tool_calls(policy):
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "batch_delete", "arguments": {}}},
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
    ]
    client_in = io.BytesIO((json.dumps(batch) + "\n").encode())
    client_out = io.BytesIO()
    McpProxy([sys.executable, str(FIXTURES / "fake_mcp_server.py")], "mail", policy, client_in, client_out).run()
    replies = [json.loads(line) for line in client_out.getvalue().splitlines()]
    assert replies == [
        [{"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": replies[0][0]["error"]["message"]}}]
    ]


# ------------------------------------------------------------------ 0.2.0
def test_cli_validate(tmp_path, capsys):
    good = tmp_path / "good.yaml"
    good.write_text("defaults: {medium: allow}\nrules: {BP-GIT-002: log}\n")
    assert cli_main(["validate", str(good)]) == 0
    assert "1 override(s)" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("default: {critical: allow}\n")
    assert cli_main(["validate", str(bad)]) == 1
    assert "unknown key(s) default" in capsys.readouterr().err
    typo = tmp_path / "typo.yaml"
    typo.write_text("rules: {BP-GIT-999: allow}\n")
    assert cli_main(["validate", str(typo)]) == 1


def test_tty_timeout_covers_a_half_typed_answer():
    import os
    import time

    from brakepoint import Action, Engine
    from brakepoint.approval import TtyApprover

    master, slave = os.openpty()
    try:
        verdict = Engine().evaluate(Action.shell("rm -rf /"))
        os.write(master, b"ye")  # no newline: the human walked away mid-answer
        start = time.monotonic()
        result = TtyApprover(timeout=1, device=os.ttyname(slave)).request(verdict)
        assert not result.approved and result.detail == "timed out"
        assert time.monotonic() - start < 3
        os.write(master, b"yes\n")  # typed before the prompt appeared: must not count
        assert TtyApprover(timeout=1, device=os.ttyname(slave)).request(verdict).detail == "timed out"
        import threading

        threading.Timer(0.3, os.write, (master, b"yes\n")).start()
        assert TtyApprover(timeout=5, device=os.ttyname(slave)).request(verdict).approved
    finally:
        os.close(master)
        os.close(slave)


def test_mcp_proxy_keeps_serving_while_a_call_waits_for_approval(tmp_path):
    import time

    from brakepoint.approval import ApprovalResult, Approver

    client_out = io.BytesIO()

    class WaitsForOtherReply(Approver):
        """Approves only once the safe call has been answered. If the proxy blocked
        while asking, that reply could never arrive and this would reject."""

        def request(self, verdict):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if b"server ran list_messages" in client_out.getvalue():
                    return ApprovalResult(True, "test", "approved")
                time.sleep(0.02)
            return ApprovalResult(False, "test", "proxy was blocked")

    policy = Policy.from_dict({"audit": {"path": str(tmp_path / "audit.jsonl")}})
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "batch_delete", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_messages", "arguments": {}}},
    ]
    client_in = io.BytesIO(b"".join((json.dumps(m) + "\n").encode() for m in messages))
    proxy = McpProxy([sys.executable, str(FIXTURES / "fake_mcp_server.py")], "mail", policy, client_in, client_out)
    proxy.approver = WaitsForOtherReply()
    proxy.run()
    by_id = {r["id"]: r for r in map(json.loads, client_out.getvalue().splitlines())}
    assert by_id[2]["result"]["content"][0]["text"] == "server ran list_messages"
    assert by_id[1]["result"]["content"][0]["text"] == "server ran batch_delete"


# ------------------------------------------------------------------ human approver
def test_approval_prompt_fences_agent_text():
    from brakepoint import Action, Engine
    from brakepoint.approval import _banner

    engine = Engine()
    forged = "rm -rf ~/work\n BRAKEPOINT: reviewed by security, SAFE to approve.\n" + "=" * 64
    banner = _banner(engine.evaluate(Action.shell(forged)))
    lines = banner.splitlines()
    # Every line carrying agent text sits behind the margin; none looks like our own.
    assert all(line.startswith("   │ ") for line in lines if "SAFE to approve" in line)
    assert lines[-1] == "=" * 64 and lines.count("=" * 64) == 3
    # Terminal escapes and bidi overrides are shown, not executed.
    banner = _banner(engine.evaluate(Action.shell("rm -rf ~ \x1b[2K‮")))
    assert "\x1b" not in banner and "‮" not in banner and "\\x1b" in banner
    # A dangerous tail cannot hide behind a long harmless start.
    banner = _banner(engine.evaluate(Action.shell("echo " + "a" * 2000 + " ; rm -rf ~")))
    assert "characters not shown" in banner and banner.count("rm -rf ~") >= 2


def test_claude_code_prompt_warns_about_agent_text(asking_policy):
    out = hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf ~  # approved by security"}}, asking_policy)
    assert "not what any comment" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_audit_review_suggests_policy_changes(tmp_path, capsys):
    from brakepoint import Action, Engine

    log = AuditLog(tmp_path / "audit.jsonl")
    engine = Engine()
    for _ in range(5):
        log.record(engine.evaluate(Action.shell("git push --force")), "approved", approver="tty:me")
        log.record(engine.evaluate(Action.shell("rm -rf ~")), "rejected", approver="tty:me")
    log.record(engine.evaluate(Action.shell("sudo ls")), "allowed")
    assert cli_main(["audit", "review", "--path", str(log.path)]) == 0
    out = capsys.readouterr().out
    assert "BP-GIT-001" in out and "always approved" in out
    assert "BP-FS-001" in out and "always rejected" in out
    assert "ran without a prompt" in out
