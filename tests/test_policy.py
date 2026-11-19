"""Policy semantics: overrides, protected targets, allowlists, locked rules."""

import pytest

from brakepoint import Action, Engine, Policy
from brakepoint.policy import PolicyError


def engine_with(data):
    return Engine(Policy.from_dict(data))


def test_defaults_map_severity_to_decision():
    engine = Engine()
    assert engine.evaluate(Action.shell("terraform destroy")).decision == "approve"  # critical
    assert engine.evaluate(Action.shell("sudo apt update")).decision == "log"  # medium


def test_protected_marker_escalates_critical_to_deny():
    engine = Engine()
    verdict = engine.evaluate(Action.shell("az group delete -n rg-prod --yes"))
    assert verdict.decision == "deny"
    assert verdict.top.protected


def test_protected_marker_ignores_lookalike_words():
    engine = Engine()
    verdict = engine.evaluate(Action.shell("az group delete -n rg-product-dev --yes"))
    assert verdict.decision == "approve"


def test_rule_override():
    engine = engine_with({"rules": {"BP-GIT-002": "log"}})
    assert engine.evaluate(Action.shell("git reset --hard")).decision == "log"


def test_locked_rule_cannot_be_overridden():
    engine = engine_with({"rules": {"BP-SELF-001": "allow"}, "allow": [r"brakepoint approve \w+"]})
    assert engine.evaluate(Action.shell("brakepoint approve abc123")).decision == "deny"


def test_allowlisted_segment_is_skipped_but_not_the_rest():
    engine = engine_with({"allow": [r"rm -rf (\./)?(node_modules|dist)/?"]})
    assert engine.evaluate(Action.shell("rm -rf node_modules")).decision == "allow"
    assert engine.evaluate(Action.shell('rm -rf "node_modules"')).decision == "allow"
    assert engine.evaluate(Action.shell("rm -rf node_modules && rm -rf /")).decision == "approve"


def test_strict_mode_denies_everything_critical():
    engine = engine_with({"defaults": {"critical": "deny"}})
    assert engine.evaluate(Action.shell("terraform destroy")).decision == "deny"


def test_policy_file_is_discovered(tmp_path, monkeypatch):
    (tmp_path / ".brakepoint.yaml").write_text("defaults:\n  high: deny\n")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    monkeypatch.delenv("BRAKEPOINT_POLICY", raising=False)
    policy = Policy.load(start=sub)
    assert policy.defaults["high"] == "deny"


# ------------------------------------------------------------------ regressions
@pytest.mark.parametrize(
    "data",
    [
        {"default": {"critical": "allow"}},  # typo for defaults
        {"approval": {"timeout": 5}},
        {"approval": {"unattended_modes": "bypassPermissions"}},  # string, not list
        {"protected": {"markers": "prod"}},
        {"allow": "rm -rf build"},
        {"defaults": ["critical"]},
        {"approval": {"timeout_seconds": "soon"}},
    ],
)
def test_malformed_policies_are_rejected(data):
    with pytest.raises(PolicyError):
        Policy.from_dict(data)


def test_override_of_unknown_rule_is_rejected():
    with pytest.raises(PolicyError, match="BP-GIT-999"):
        Engine(Policy.from_dict({"rules": {"BP-GIT-999": "allow"}}))


@pytest.mark.parametrize(
    "command",
    [
        'echo \'{"decision": "approve"}\' > ~/.local/state/brakepoint/queue/decided/ab12cd34.json',
        "python3 rewrite.py ~/.local/state/brakepoint/audit.jsonl",
        "cat > ~/.config/brakepoint/policy.yaml",
    ],
)
def test_agent_cannot_touch_default_brakepoint_state(command):
    verdict = Engine(Policy()).evaluate(Action.shell(command))
    assert verdict.decision == "deny"
    assert verdict.top.rule.locked


def test_agent_cannot_touch_custom_queue_audit_or_policy_paths(tmp_path):
    policy_file = tmp_path / "etc" / "policy.yaml"
    policy_file.parent.mkdir()
    policy_file.write_text(
        "approval: {backend: queue, queue_dir: /srv/bp/queue}\naudit: {path: /var/log/bp/audit.jsonl}\n"
    )
    engine = Engine(Policy.load(policy_file))
    for action in (
        Action.shell("echo approve > /srv/bp/queue/decided/x.json"),
        Action.file("/var/log/bp/audit.jsonl"),
        Action.shell(f"sed -i s/deny/allow/ {policy_file}"),
    ):
        verdict = engine.evaluate(action)
        assert (verdict.decision, verdict.top.rule.id) == ("deny", "BP-SELF-002"), action.text
    assert engine.evaluate(Action.shell("ls /srv/bp/queue-old")).decision == "allow"


@pytest.mark.parametrize(
    "action",
    [
        Action.sql("DROP/**/TABLE users"),
        Action.sql("DROP -- harmless\nTABLE users"),
        Action.shell("rm${IFS}-rf${IFS}/"),
        Action.shell("rm$IFS-rf$IFS/"),
    ],
)
def test_obfuscated_spacing_is_seen_through(action):
    assert Engine(Policy()).evaluate(action).decision == "approve"


@pytest.mark.parametrize(
    "command",
    ["sudo echo " + "x" * 300_000, "rm -x " * 60_000, "git push x " * 40_000, "a://b" * 60_000],
)
def test_long_actions_are_fast_and_go_to_a_human(command):
    import time

    from brakepoint.redact import redact

    start = time.perf_counter()
    verdict = Engine(Policy()).evaluate(Action.shell(command))
    redact(command)
    assert time.perf_counter() - start < 5
    assert verdict.decision == "approve"
    assert "BP-SIZE-001" in {m.rule.id for m in verdict.matches}


def test_padding_does_not_hide_a_destructive_command():
    assert Engine(Policy()).evaluate(Action.shell("rm -rf / # " + "x" * 100_000)).top.rule.id == "BP-FS-001"
    assert Engine(Policy()).evaluate(Action.shell("brakepoint approve ab12 " + "x" * 50_000)).decision == "deny"


def test_size_rule_can_be_relaxed_by_policy():
    verdict = Engine(Policy.from_dict({"rules": {"BP-SIZE-001": "allow"}})).evaluate(
        Action.shell("echo " + "x" * 20_000)
    )
    assert verdict.decision == "allow"
