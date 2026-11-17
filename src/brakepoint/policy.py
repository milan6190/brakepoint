"""Policy: how catalog matches turn into decisions."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DECISIONS = ("allow", "log", "approve", "deny")
POLICY_FILENAMES = (".brakepoint.yaml", ".brakepoint.yml")


class PolicyError(ValueError):
    pass


def decision_rank(decision: str) -> int:
    return DECISIONS.index(decision)


DEFAULT_POLICY_YAML = """\
# Brakepoint policy. Place this file at the root of your project.
# Agents cannot edit it: writes to .brakepoint.yaml are blocked by rule BP-SELF-001.
version: 1

# What to do for each severity when a catalog rule matches.
#   allow   - let it run, no record
#   log     - let it run, record it in the audit log
#   approve - stop and ask a human, outside the agent's control
#   deny    - block it; a human has to do it themselves
defaults:
  critical: approve
  high: approve
  medium: log
  unmatched: allow

# Words that mark production targets. A critical action whose command
# mentions one of them is escalated to `protected_action`, and a high one is
# escalated to at least `approve`.
protected:
  markers: [prod, production, prd, live]
  protected_action: deny

# Who approves. auto = the agent harness's own prompt when running as a hook,
# otherwise the terminal (/dev/tty), otherwise deny.
# Other options: tty, queue (approve from another terminal with
# `brakepoint approve <id>`), deny.
approval:
  backend: auto
  timeout_seconds: 300
  # Claude Code permission modes in which no human will see an "ask" prompt.
  # Actions that need approval are denied in these modes.
  unattended_modes: [bypassPermissions, dontAsk]

# Per-rule overrides, by rule id. Locked rules (BP-SELF-*) cannot be relaxed.
rules: {}
#  BP-GIT-002: log
#  BP-EXEC-003: allow

# Command segments that are always fine, as full-match regexes.
allow: []
#  - 'rm -rf (\\./)?(node_modules|dist|build|\\.pytest_cache|__pycache__)/?'

# Extra catalog files with your own rules.
catalogs: []

audit:
  enabled: true
  path: ~/.local/state/brakepoint/audit.jsonl
"""


@dataclass
class Policy:
    defaults: dict[str, str] = field(
        default_factory=lambda: {"critical": "approve", "high": "approve", "medium": "log", "unmatched": "allow"}
    )
    protected_markers: list[str] = field(default_factory=lambda: ["prod", "production", "prd", "live"])
    protected_action: str = "deny"
    approval_backend: str = "auto"
    approval_timeout: int = 300
    unattended_modes: list[str] = field(default_factory=lambda: ["bypassPermissions", "dontAsk"])
    queue_dir: str = "~/.local/state/brakepoint/queue"
    rule_overrides: dict[str, str] = field(default_factory=dict)
    allow: list[re.Pattern] = field(default_factory=list)
    catalogs: list[str] = field(default_factory=list)
    audit_enabled: bool = True
    audit_path: str = "~/.local/state/brakepoint/audit.jsonl"
    source: str = "builtin-defaults"

    _marker_re: re.Pattern | None = None

    @property
    def marker_re(self) -> re.Pattern | None:
        if not self.protected_markers:
            return None
        if self._marker_re is None:
            words = "|".join(re.escape(m) for m in self.protected_markers)
            self._marker_re = re.compile(rf"(?i)(?<![A-Za-z0-9])(?:{words})(?![A-Za-z0-9])")
        return self._marker_re

    def is_allowlisted(self, segment: str) -> bool:
        return any(p.fullmatch(segment.strip()) for p in self.allow)

    # ----------------------------------------------------------- loading
    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "<dict>") -> Policy:
        # Unknown keys are errors, not silently ignored: a typo such as `default:` for
        # `defaults:` would otherwise quietly fall back to a weaker policy.
        _check_keys(data, TOP_LEVEL_KEYS, source, "")
        policy = cls(source=source)
        defaults = _mapping(data, "defaults", source)
        for key, value in defaults.items():
            if key not in ("critical", "high", "medium", "unmatched"):
                raise PolicyError(f"{source}: unknown defaults key {key!r}")
            _check_decision(value, f"{source}: defaults.{key}")
            policy.defaults[key] = value

        protected = _mapping(data, "protected", source)
        _check_keys(protected, {"markers", "protected_action"}, source, "protected.")
        if "markers" in protected:
            policy.protected_markers = [str(m) for m in _str_list(protected["markers"], f"{source}: protected.markers")]
        if "protected_action" in protected:
            _check_decision(protected["protected_action"], f"{source}: protected.protected_action")
            policy.protected_action = protected["protected_action"]

        approval = _mapping(data, "approval", source)
        _check_keys(approval, {"backend", "timeout_seconds", "unattended_modes", "queue_dir"}, source, "approval.")
        backend = approval.get("backend", policy.approval_backend)
        if backend not in ("auto", "harness", "tty", "queue", "deny"):
            raise PolicyError(f"{source}: approval.backend must be auto, harness, tty, queue or deny")
        policy.approval_backend = backend
        try:
            policy.approval_timeout = int(approval.get("timeout_seconds", policy.approval_timeout))
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"{source}: approval.timeout_seconds must be a number") from exc
        if "unattended_modes" in approval:
            policy.unattended_modes = _str_list(approval["unattended_modes"], f"{source}: approval.unattended_modes")
        policy.queue_dir = approval.get("queue_dir", policy.queue_dir)

        for rule_id, value in _mapping(data, "rules", source).items():
            _check_decision(value, f"{source}: rules.{rule_id}")
            policy.rule_overrides[str(rule_id)] = value

        for pattern in _str_list(data.get("allow") or [], f"{source}: allow"):
            try:
                policy.allow.append(re.compile(pattern))
            except re.error as exc:
                raise PolicyError(f"{source}: bad allow pattern {pattern!r}: {exc}") from exc

        base = Path(source).parent if source not in ("<dict>", "builtin-defaults") else Path.cwd()
        for path in _str_list(data.get("catalogs") or [], f"{source}: catalogs"):
            p = Path(path).expanduser()
            policy.catalogs.append(str(p if p.is_absolute() else base / p))

        audit = _mapping(data, "audit", source)
        _check_keys(audit, {"enabled", "path"}, source, "audit.")
        policy.audit_enabled = bool(audit.get("enabled", True))
        policy.audit_path = audit.get("path", policy.audit_path)
        return policy

    @classmethod
    def load(cls, path: str | Path | None = None, start: str | Path | None = None) -> Policy:
        found = Path(path).expanduser() if path else find_policy(start)
        if not found:
            return cls()
        data = yaml.safe_load(found.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise PolicyError(f"{found}: policy must be a mapping")
        return cls.from_dict(data, source=str(found))


TOP_LEVEL_KEYS = {"version", "defaults", "protected", "approval", "rules", "allow", "catalogs", "audit"}


def _check_keys(data: dict, allowed: set[str], source: str, prefix: str) -> None:
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        raise PolicyError(f"{source}: unknown key(s) {', '.join(prefix + k for k in unknown)}")


def _mapping(data: dict, key: str, source: str) -> dict:
    value = data.get(key) or {}
    if not isinstance(value, dict):
        raise PolicyError(f"{source}: {key} must be a mapping")
    return value


def _str_list(value: Any, where: str) -> list:
    # A bare string would otherwise be iterated character by character.
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a list")
    return value


def _check_decision(value: str, where: str) -> None:
    if value not in DECISIONS:
        raise PolicyError(f"{where} must be one of {DECISIONS}, got {value!r}")


def find_policy(start: str | Path | None = None) -> Path | None:
    """BRAKEPOINT_POLICY, then .brakepoint.yaml from start upward, then user config."""
    env = os.environ.get("BRAKEPOINT_POLICY")
    if env:
        return Path(env).expanduser()
    here = Path(start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        for name in POLICY_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    user = Path("~/.config/brakepoint/policy.yaml").expanduser()
    return user if user.is_file() else None
