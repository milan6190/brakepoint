"""Hash-chained, append-only audit log (JSON Lines).

Every entry stores the SHA-256 of the previous entry, so deleting or editing a
line breaks the chain and `brakepoint audit verify` reports where. This is
tamper-evident, not tamper-proof: keep the file outside the agent's reach, or
ship it to a log store the agent cannot write to.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .redact import redact_obj

GENESIS = "0" * 64

try:  # POSIX file locking; on other platforms writes are best-effort.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@contextmanager
def _locked(handle):
    if fcntl:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        if fcntl:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _last_hash(handle) -> str:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size == 0:
        return GENESIS
    block = min(size, 65536)
    handle.seek(size - block)
    lines = handle.read(block).decode("utf-8", errors="replace").strip().splitlines()
    for line in reversed(lines):
        try:
            return json.loads(line)["hash"]
        except (ValueError, KeyError):
            continue
    return GENESIS


class AuditLog:
    def __init__(self, path: str | Path, enabled: bool = True):
        self.path = Path(path).expanduser()
        self.enabled = enabled

    def record(self, verdict, outcome: str, approver: str = "", extra: dict | None = None) -> dict | None:
        """outcome: allowed | blocked | approved | rejected | asked."""
        if not self.enabled:
            return None
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "host": socket.gethostname(),
            "user": _user(),
            "outcome": outcome,
            "approver": approver,
            **redact_obj(verdict.to_dict()),
        }
        if extra:
            entry["context"] = redact_obj(extra)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+b") as handle, _locked(handle):
            entry["prev"] = _last_hash(handle)
            entry["hash"] = _digest(entry)
            handle.seek(0, os.SEEK_END)
            handle.write((json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
        return entry

    def entries(self):
        if not self.path.exists():
            return
        with open(self.path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                line = line.strip()
                if line:
                    yield number, line

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        count = 0
        for number, line in self.entries() or []:
            try:
                entry = json.loads(line)
            except ValueError:
                return False, f"line {number}: not valid JSON"
            if entry.get("prev") != prev:
                return False, f"line {number}: chain broken (an entry before it was removed or edited)"
            if _digest(entry) != entry.get("hash"):
                return False, f"line {number}: entry was modified after it was written"
            prev = entry["hash"]
            count += 1
        return True, f"{count} entries, chain intact"


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"
