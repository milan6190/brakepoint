"""Evaluate an action against the catalog and the policy."""

from __future__ import annotations

from dataclasses import dataclass, field

from .actions import Action, _dequote
from .catalog import SEVERITIES, Catalog, Rule, load_catalog
from .policy import Policy, decision_rank


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

    def evaluate(self, action: Action, extra_matches: list[Match] | None = None) -> Verdict:
        matches = self._match(action)
        for child in action.children:
            matches.extend(self._match(child))
        matches.extend(extra_matches or [])
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
        text_candidates = action.text_candidates()
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
