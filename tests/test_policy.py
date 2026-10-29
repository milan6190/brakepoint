"""Policy semantics: overrides, protected targets, allowlists, locked rules."""

from brakepoint import Action, Engine, Policy


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
