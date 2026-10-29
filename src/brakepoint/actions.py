"""Normalise agent actions into text the catalog rules can match."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# Splits a shell command into segments. This is deliberately coarse: it is not
# a shell parser. Over-splitting only adds candidates (more chances to match),
# and the full text is always checked as well.
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n|`|\$\()\s*")
_LINE_CONTINUATION = re.compile(r"\\\r?\n")
_WHITESPACE = re.compile(r"[ \t]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

# Argument keys that usually carry a command or a query inside a tool call.
SHELL_ARG_KEYS = {"command", "cmd", "shell", "script", "bash", "commands", "code"}
SQL_ARG_KEYS = {"query", "sql", "statement", "statements", "queries"}


@dataclass
class Action:
    """One thing an agent wants to do.

    kind is one of: shell, tool, sql, file, url.
    """

    kind: str
    text: str
    name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    origin: str = "cli"
    children: list[Action] = field(default_factory=list)

    # ----------------------------------------------------------- builders
    @classmethod
    def shell(cls, command: str, origin: str = "cli") -> Action:
        return cls(kind="shell", text=command, origin=origin)

    @classmethod
    def sql(cls, statement: str, origin: str = "cli") -> Action:
        return cls(kind="sql", text=statement, origin=origin)

    @classmethod
    def file(cls, path: str, mode: str = "write", origin: str = "cli") -> Action:
        return cls(kind="file", text=f"{mode} {path}", name=mode, origin=origin)

    @classmethod
    def url(cls, url: str, origin: str = "cli") -> Action:
        return cls(kind="url", text=url, origin=origin)

    @classmethod
    def tool(cls, name: str, args: dict[str, Any] | None = None, origin: str = "cli") -> Action:
        args = args or {}
        try:
            args_text = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            args_text = str(args)
        action = cls(kind="tool", text=f"{name} {args_text}", name=name, args=args, origin=origin)
        action.children = list(_embedded_actions(args, origin))
        return action

    # ----------------------------------------------------------- candidates
    def display(self) -> str:
        if self.kind == "tool":
            return self.text
        return self.text.strip()

    def text_candidates(self) -> list[str]:
        """Strings rules are matched against (segments, de-quoted forms, full text)."""
        text = _LINE_CONTINUATION.sub(" ", self.text)
        full = _WHITESPACE.sub(" ", text).strip()
        candidates: list[str] = []
        if self.kind == "shell":
            for segment in _SEGMENT_SPLIT.split(full):
                segment = segment.strip()
                if segment:
                    candidates.append(segment)
        candidates.append(full)
        # De-quoted variants defeat trivial evasion like  r''m -rf /  or "rm" -rf /
        for candidate in list(candidates):
            dequoted = _dequote(candidate)
            if dequoted != candidate:
                candidates.append(dequoted)
        return _unique(candidates)

    def name_candidates(self) -> list[str]:
        if self.kind != "tool" or not self.name:
            return []
        return [normalise_tool_name(self.name)]


def normalise_tool_name(name: str) -> str:
    """mcp__gmail__batchDelete -> 'mcp gmail batch_delete'."""
    parts = [p for p in re.split(r"__|[.:/]", name) if p]
    words = []
    for part in parts:
        part = _CAMEL.sub("_", part)
        part = re.sub(r"[-\s]+", "_", part)
        words.append(part.lower())
    return " ".join(words)


def _dequote(text: str) -> str:
    return re.sub(r"""['"\\]""", "", text)


def _unique(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _embedded_actions(value: Any, origin: str, key: str = ""):
    """Find shell commands and SQL hidden inside tool arguments."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _embedded_actions(v, origin, str(k).lower())
    elif isinstance(value, list):
        for item in value:
            yield from _embedded_actions(item, origin, key)
    elif isinstance(value, str) and value.strip():
        if key in SHELL_ARG_KEYS:
            yield Action.shell(value, origin=origin)
        elif key in SQL_ARG_KEYS:
            yield Action.sql(value, origin=origin)
