"""Load and validate the destructive-action catalog."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

SEVERITIES = ("medium", "high", "critical")
REVERSIBILITY = ("reversible", "hard-to-reverse", "irreversible")
KINDS = ("shell", "tool", "sql", "file", "url")
CATEGORIES = (
    "data-destruction",
    "backup-destruction",
    "credential-access",
    "privilege-escalation",
    "exposure",
    "sandbox-escape",
    "code-execution",
    "outbound-action",
    "financial",
    "self-tamper",
    "history-rewrite",
    "availability",
)
_ID_RE = re.compile(r"^BP-[A-Z0-9]+-\d{3}$")


class CatalogError(ValueError):
    """Raised when a catalog file is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    platform: str
    severity: str
    reversibility: str
    kinds: tuple[str, ...]
    patterns: tuple[re.Pattern, ...]
    unless: tuple[re.Pattern, ...] = ()
    field: str = "text"
    locked: bool = False
    why: str = ""
    safer: str = ""
    refs: tuple[str, ...] = ()
    source: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITIES.index(self.severity)

    def matches(self, candidate: str) -> bool:
        if not any(p.search(candidate) for p in self.patterns):
            return False
        return not any(u.search(candidate) for u in self.unless)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "platform": self.platform,
            "severity": self.severity,
            "reversibility": self.reversibility,
            "kinds": list(self.kinds),
            "locked": self.locked,
            "why": self.why,
            "safer": self.safer,
            "refs": list(self.refs),
        }


@dataclass
class Catalog:
    rules: list[Rule] = field(default_factory=list)

    def __iter__(self):
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def get(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


def _compile(patterns: Iterable[str], rule_id: str) -> tuple[re.Pattern, ...]:
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:  # pragma: no cover - exercised via validate
            raise CatalogError(f"{rule_id}: invalid regex {pattern!r}: {exc}") from exc
    return tuple(compiled)


def _parse_rule(raw: dict, source: str) -> Rule:
    rule_id = raw.get("id", "<missing id>")
    for key in ("id", "title", "category", "platform", "severity", "reversibility", "patterns"):
        if key not in raw:
            raise CatalogError(f"{source}: rule {rule_id} is missing '{key}'")
    if not _ID_RE.match(raw["id"]):
        raise CatalogError(f"{source}: rule id {raw['id']!r} must look like BP-AREA-000")
    if raw["severity"] not in SEVERITIES:
        raise CatalogError(f"{rule_id}: severity must be one of {SEVERITIES}")
    if raw["reversibility"] not in REVERSIBILITY:
        raise CatalogError(f"{rule_id}: reversibility must be one of {REVERSIBILITY}")
    if raw["category"] not in CATEGORIES:
        raise CatalogError(f"{rule_id}: category must be one of {CATEGORIES}")
    kinds = tuple(raw.get("kinds", ["shell", "tool"]))
    for kind in kinds:
        if kind not in KINDS:
            raise CatalogError(f"{rule_id}: unknown kind {kind!r}")
    field_name = raw.get("field", "text")
    if field_name not in ("text", "name"):
        raise CatalogError(f"{rule_id}: field must be 'text' or 'name'")
    if not raw["patterns"]:
        raise CatalogError(f"{rule_id}: needs at least one pattern")
    return Rule(
        id=raw["id"],
        title=raw["title"],
        category=raw["category"],
        platform=raw["platform"],
        severity=raw["severity"],
        reversibility=raw["reversibility"],
        kinds=kinds,
        patterns=_compile(raw["patterns"], rule_id),
        unless=_compile(raw.get("unless", []), rule_id),
        field=field_name,
        locked=bool(raw.get("locked", False)),
        why=raw.get("why", "").strip(),
        safer=raw.get("safer", "").strip(),
        refs=tuple(raw.get("refs", [])),
        source=source,
    )


def _load_text(text: str, source: str) -> list[Rule]:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise CatalogError(f"{source}: expected a top-level 'rules' list")
    return [_parse_rule(raw, source) for raw in data["rules"]]


def builtin_files() -> list[tuple[str, str]]:
    """Return (name, text) for every built-in catalog file, in a stable order."""
    package = resources.files("brakepoint") / "catalog"
    files = sorted(p for p in package.iterdir() if p.name.endswith(".yaml"))
    return [(p.name, p.read_text(encoding="utf-8")) for p in files]


def load_catalog(extra_paths: Iterable[str | Path] = ()) -> Catalog:
    """Load the built-in catalog plus any extra catalog files from a policy."""
    rules: list[Rule] = []
    for name, text in builtin_files():
        rules.extend(_load_text(text, f"builtin:{name}"))
    for path in extra_paths:
        path = Path(path).expanduser()
        rules.extend(_load_text(path.read_text(encoding="utf-8"), str(path)))
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise CatalogError(f"duplicate rule id {rule.id} ({rule.source})")
        seen.add(rule.id)
    return Catalog(rules)
