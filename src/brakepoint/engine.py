"""Evaluate an action against the catalog and the policy."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .actions import Action, _dequote
from .catalog import SEVERITIES, Catalog, Rule, load_catalog
from .policy import Policy, PolicyError, decision_rank

# Longer candidates are matched on their head and tail only. Several catalog patterns
# scan ahead from a keyword, which is quadratic when an agent repeats the keyword; the
# cap keeps every evaluation fast, and BP-SIZE-001 sends oversized actions to a human.
MAX_CANDIDATE = 16_000

SIZE_RULE = Rule(
    id="BP-SIZE-001",
    title="Action too long to check automatically",
    category="code-execution",
    platform="brakepoint",
    severity="high",
    reversibility="irreversible",
    kinds=("shell", "tool", "sql", "file", "url"),
    patterns=(re.compile(r".^"),),  # never matches text; added by the engine
    why=f"Over {MAX_CANDIDATE:,} characters, only the start and end were checked against the catalog.",
    safer="Split the work into smaller steps, or write the content to a file and review it first.",
    source="engine",
)
# Rule ids that are not in the catalog files but can still be overridden in a policy.
SYNTHETIC_RULE_IDS = {"BP-SIZE-001", "BP-HINT-001"}


@dataclass
class Match:
    rule: Rule
    candidate: str
    protected: bool
    decision: str
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "category": self.rule.category,
            "reversibility": self.rule.reversibility,
            "protected_target": self.protected,
            "decision": self.decision,
            "note": self.note,
        }


@dataclass
class Verdict:
    action: Action
    decision: str
    matches: list[Match] = field(default_factory=list)

    @property
    def top(self) -> Match | None:
        if not self.matches:
            return None
        return max(
            self.matches,
            key=lambda m: (decision_rank(m.decision), m.rule.severity_rank, m.rule.locked),
        )

    @property
    def needs_human(self) -> bool:
        return self.decision in ("approve", "deny")

    def reason(self, audience: str = "agent") -> str:
        """Explanation shown to the agent (to adapt) or the human (to decide)."""
        top = self.top
        if top is None:
            return "No catalogued risk."
        rule = top.rule
        lines = [
            f"Brakepoint {self.decision.upper()}: [{rule.id}] {rule.title} ({rule.severity}, {rule.reversibility})."
        ]
        if top.protected:
            lines.append("The command targets something that looks like production.")
        if rule.why:
            lines.append(f"Why: {rule.why}")
        if rule.safer:
            lines.append(f"Safer: {rule.safer}")
        others = sorted({m.rule.id for m in self.matches if m is not top})
        if others:
            lines.append("Also matched: " + ", ".join(others))
        if audience == "agent" and self.decision == "deny":
            lines.append(
                "Do not retry this action in another form. Explain to the user what you were "
                "trying to do and let them decide."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "action": {"kind": self.action.kind, "text": self.action.display(), "origin": self.action.origin},
            "matches": [m.to_dict() for m in self.matches],
        }


class Engine:
    def __init__(self, policy: Policy | None = None, catalog: Catalog | None = None):
        self.policy = policy or Policy()
        self.catalog = catalog or load_catalog(self.policy.catalogs)
        unknown = sorted(set(self.policy.rule_overrides) - {r.id for r in self.catalog} - SYNTHETIC_RULE_IDS)
        if unknown:
            raise PolicyError(f"{self.policy.source}: rules override unknown rule id(s): {', '.join(unknown)}")
        self_rule = _self_paths_rule(self.policy)
        if self_rule is not None:
            self.catalog = Catalog([*self.catalog.rules, self_rule])

    def evaluate(self, action: Action, extra_matches: list[Match] | None = None) -> Verdict:
        matches = self._match(action)
        for child in action.children:
            matches.extend(self._match(child))
        matches.extend(extra_matches or [])
        oversized = next(
            (c for a in (action, *action.children) for c in a.text_candidates() if len(c) > MAX_CANDIDATE), None
        )
        if oversized is not None:
            decision, note = self.decide(SIZE_RULE, protected=False)
            matches.append(Match(SIZE_RULE, oversized[:200], False, decision, note))
        matches = _dedupe(matches)
        if not matches:
            return Verdict(action, self.policy.defaults.get("unmatched", "allow"))
        decision = max((m.decision for m in matches), key=decision_rank)
        return Verdict(action, decision, matches)

    def decide(self, rule: Rule, protected: bool) -> tuple[str, str]:
        """Policy decision for one matched rule. Returns (decision, note)."""
        if rule.locked:
            return "deny", "locked rule"
        if rule.id in self.policy.rule_overrides:
            decision = self.policy.rule_overrides[rule.id]
            note = "policy override"
        else:
            decision = self.policy.defaults.get(rule.severity, "approve")
            note = ""
        if protected:
            if rule.severity == "critical":
                floor = self.policy.protected_action
            elif rule.severity == "high":
                floor = "approve"
            else:
                floor = decision
            if decision_rank(floor) > decision_rank(decision):
                decision, note = floor, "protected target"
        return decision, note

    # ----------------------------------------------------------- internals
    def _match(self, action: Action) -> list[Match]:
        text_candidates = _bounded(action.text_candidates())
        name_candidates = action.name_candidates()
        allowed = [c for c in text_candidates if self.policy.allow and self.policy.is_allowlisted(c)]
        found: list[Match] = []
        for rule in self.catalog:
            if action.kind not in rule.kinds:
                continue
            pool = name_candidates if rule.field == "name" else text_candidates
            for candidate in pool:
                if not rule.locked and _covered_by_allowlist(candidate, allowed, action):
                    continue
                if rule.matches(candidate):
                    protected = bool(self.policy.marker_re and self.policy.marker_re.search(candidate))
                    decision, note = self.decide(rule, protected)
                    found.append(Match(rule, candidate, protected, decision, note))
                    break
        return found


def _bounded(candidates: list[str]) -> list[str]:
    out = []
    for c in candidates:
        if len(c) > MAX_CANDIDATE:
            half = MAX_CANDIDATE // 2
            out += [c[:half], c[-half:]]
        else:
            out.append(c)
    return out


def _self_paths_rule(policy: Policy) -> Rule | None:
    """A locked rule for the files this policy itself relies on: the policy file, the
    approval queue, the audit log, and extra catalogs. Their default locations are
    covered by BP-SELF-001; this covers custom ones."""
    paths = [policy.queue_dir, policy.audit_path, *policy.catalogs]
    if policy.source not in ("<dict>", "builtin-defaults"):
        paths.append(policy.source)
    home = str(Path.home())
    forms: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        full = os.path.abspath(os.path.expanduser(str(raw)))
        forms.add(full)
        if home != "/" and full.startswith(home + os.sep):
            rest = full[len(home) :]
            forms.update({"~" + rest, "$HOME" + rest, "${HOME}" + rest})
    if not forms:
        return None
    return Rule(
        id="BP-SELF-002",
        title="Agent touches Brakepoint's policy, approval queue, or audit log",
        category="self-tamper",
        platform="brakepoint",
        severity="critical",
        reversibility="irreversible",
        kinds=("shell", "file", "tool"),
        patterns=tuple(re.compile(re.escape(f) + r"(?![\w.-])") for f in sorted(forms)),
        locked=True,
        why="These files decide what the agent may do and record what it did. An agent that can write them can approve itself or erase its tracks.",
        safer="Ask the human to inspect or change these files themselves.",
        source="policy-paths",
    )


def _covered_by_allowlist(candidate: str, allowed: list[str], action: Action) -> bool:
    """A candidate is skipped if it is an allowlisted segment, or if it is the
    full command and every segment of it is allowlisted."""
    if not allowed:
        return False
    if candidate in allowed or _dequote(candidate) in allowed:
        return True
    if action.kind == "shell":
        segments = [c for c in action.text_candidates() if c != candidate and c in candidate]
        return bool(segments) and all(s in allowed or _dequote(s) in allowed for s in segments if s.strip())
    return False


def _dedupe(matches: list[Match]) -> list[Match]:
    best: dict[str, Match] = {}
    for m in matches:
        current = best.get(m.rule.id)
        if current is None or decision_rank(m.decision) > decision_rank(current.decision):
            best[m.rule.id] = m
    return sorted(
        best.values(),
        key=lambda m: (-decision_rank(m.decision), -SEVERITIES.index(m.rule.severity), m.rule.id),
    )


def evaluate(action: Action, policy: Policy | None = None) -> Verdict:
    """Convenience wrapper for one-off checks."""
    return Engine(policy).evaluate(action)
