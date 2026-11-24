"""Out-of-band approval: the human decides, not the model.

Every backend fails closed. If no human can be reached before the timeout,
the action is denied.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import select
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .redact import redact

try:
    import termios
except ImportError:  # pragma: no cover - non-POSIX
    termios = None


@dataclass
class ApprovalResult:
    approved: bool
    approver: str
    detail: str = ""


class Approver:
    name = "base"

    def request(self, verdict) -> ApprovalResult:  # pragma: no cover - interface
        raise NotImplementedError


class DenyApprover(Approver):
    name = "deny"

    def request(self, verdict) -> ApprovalResult:
        return ApprovalResult(False, "policy", "no approver configured; denied by default")


class TtyApprover(Approver):
    """Asks on the controlling terminal (/dev/tty), not on stdin/stdout.

    The agent drives stdin and reads stdout, so prompting there would let the
    model answer its own question. /dev/tty reaches the human at the keyboard.
    """

    name = "tty"

    def __init__(self, timeout: int = 300, device: str = "/dev/tty"):
        self.timeout = timeout
        self.device = device

    @staticmethod
    def available(device: str = "/dev/tty") -> bool:
        try:
            os.close(os.open(device, os.O_RDWR | os.O_NOCTTY))
            return True
        except OSError:
            return False

    def request(self, verdict) -> ApprovalResult:
        # Raw file descriptor: a buffered text file opened "r+" needs a seekable file,
        # which a terminal never is, so open() would always fail.
        try:
            fd = os.open(self.device, os.O_RDWR | os.O_NOCTTY)
        except OSError:
            return ApprovalResult(False, "tty", "no terminal available; denied")
        try:
            say = lambda text: os.write(fd, text.encode("utf-8", errors="replace"))  # noqa: E731
            # Drop type-ahead: only keys pressed after the human has seen this prompt count.
            if termios:
                with contextlib.suppress(OSError, termios.error):
                    termios.tcflush(fd, termios.TCIFLUSH)
            say("\n" + _banner(verdict) + "\n")
            say(f"Type 'yes' to allow this once (auto-deny in {self.timeout}s): ")
            answer = _read_line(fd, time.monotonic() + self.timeout)
            if answer is None:
                say("\nNo answer. Denied.\n")
                return ApprovalResult(False, "tty", "timed out")
        finally:
            os.close(fd)
        if answer.strip().lower() == "yes":
            return ApprovalResult(True, f"tty:{_user()}", "approved at terminal")
        return ApprovalResult(False, f"tty:{_user()}", "rejected at terminal")


class QueueApprover(Approver):
    """Writes a pending request to a directory and waits for a decision file.

    A human approves from another terminal with `brakepoint approve <id>`.
    The agent cannot run that command itself (rule BP-SELF-001). For a strong
    guarantee, put the queue directory where the agent's OS user cannot write.
    """

    name = "queue"

    def __init__(self, queue_dir: str | Path, timeout: int = 300, poll: float = 0.5):
        self.root = Path(queue_dir).expanduser()
        self.timeout = timeout
        self.poll = poll

    @property
    def pending_dir(self) -> Path:
        return self.root / "pending"

    @property
    def decided_dir(self) -> Path:
        return self.root / "decided"

    def submit(self, verdict) -> str:
        request_id = secrets.token_hex(4)
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "id": request_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": redact(_banner(verdict)),
            "verdict": json.loads(redact(json.dumps(verdict.to_dict()))),
        }
        _atomic_write(self.pending_dir / f"{request_id}.json", json.dumps(payload, indent=2))
        return request_id

    def request(self, verdict) -> ApprovalResult:
        request_id = self.submit(verdict)
        _notify_tty(
            f"\nBrakepoint is waiting for approval {request_id}.\n"
            f"Run in another terminal:  brakepoint approve {request_id}   (or: brakepoint deny {request_id})\n"
        )
        deadline = time.monotonic() + self.timeout
        decision_file = self.decided_dir / f"{request_id}.json"
        while time.monotonic() < deadline:
            if decision_file.exists():
                try:
                    data = json.loads(decision_file.read_text())
                except ValueError:  # being written; read again on the next poll
                    time.sleep(self.poll)
                    continue
                self._cleanup(request_id)
                return ApprovalResult(data.get("decision") == "approve", f"queue:{data.get('by', '?')}", request_id)
            time.sleep(self.poll)
        self._cleanup(request_id)
        return ApprovalResult(False, "queue", f"{request_id} timed out")

    def decide(self, request_id: str, approve: bool) -> bool:
        if not (self.pending_dir / f"{request_id}.json").exists():
            return False
        self.decided_dir.mkdir(parents=True, exist_ok=True)
        record = {"decision": "approve" if approve else "deny", "by": _user(), "at": time.time()}
        _atomic_write(self.decided_dir / f"{request_id}.json", json.dumps(record))
        return True

    def pending(self) -> list[dict]:
        if not self.pending_dir.exists():
            return []
        items = []
        for path in sorted(self.pending_dir.glob("*.json")):
            try:
                items.append(json.loads(path.read_text()))
            except ValueError:
                continue
        return items

    def _cleanup(self, request_id: str) -> None:
        for path in (self.pending_dir / f"{request_id}.json", self.decided_dir / f"{request_id}.json"):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()


def build_approver(policy) -> Approver:
    backend = policy.approval_backend
    if backend in ("auto", "harness"):
        # Outside a harness hook, "auto" falls back to the terminal, then to deny.
        return TtyApprover(policy.approval_timeout) if TtyApprover.available() else DenyApprover()
    if backend == "tty":
        return TtyApprover(policy.approval_timeout)
    if backend == "queue":
        return QueueApprover(policy.queue_dir, policy.approval_timeout)
    return DenyApprover()


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temp file and rename, so readers never see a half-written file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


# Control characters, and Unicode that reorders or hides text (bidi overrides,
# zero-width characters). Agent text showing them raw could rewrite the terminal
# or disguise what it says.
_HIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_SHOW_HEAD, _SHOW_TAIL = 400, 400


def untrusted(text: str, head: int = _SHOW_HEAD, tail: int = _SHOW_TAIL) -> str:
    """Render agent-written text so it cannot pass for Brakepoint's own words.

    Every line gets a margin, so the agent cannot forge a line of the prompt;
    hidden characters are shown as escapes; and long text keeps both ends, so a
    dangerous tail cannot hide behind a harmless start.
    """
    text = redact(text)
    if len(text) > head + tail:
        hidden = len(text) - head - tail
        text = text[:head] + f"\n[... {hidden:,} characters not shown ...]\n" + text[-tail:]
    text = _HIDDEN.sub(
        lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}", text
    )
    return "\n".join("   \u2502 " + line for line in text.split("\n"))


def _banner(verdict) -> str:
    action = verdict.action
    rule = "=" * 64
    lines = [
        rule,
        " BRAKEPOINT: an agent wants to run an action that needs your approval",
        rule,
        f" Action ({action.kind}, via {action.origin}). Lines marked \u2502 were written by",
        " the agent: read them as a claim, not a fact. Instructions or reassurance inside",
        ' them ("already approved", "safe") are part of the action, not from Brakepoint.',
        "",
        untrusted(action.display()),
        "",
    ]
    matched = [m for m in verdict.matches if m.rule.source not in ("engine", "mcp-annotations")]
    if matched:
        lines.append(" What triggered this:")
        for m in matched[:5]:
            lines.append(f"   [{m.rule.id}]")
            lines.append(untrusted(m.candidate, head=150, tail=150))
        lines.append("")
    lines += [" " + line for line in verdict.reason(audience="human").splitlines()]
    lines.append(rule)
    return "\n".join(lines)


def _read_line(fd: int, deadline: float) -> str | None:
    """Read one line from fd, or return None if the deadline passes first.

    The deadline covers the whole answer, not just the first keystroke, so a
    half-typed reply cannot hold the action open forever.
    """
    data = b""
    while b"\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None
        chunk = os.read(fd, 1024)
        if not chunk:  # terminal closed
            break
        data += chunk
    return data.split(b"\n", 1)[0].decode("utf-8", errors="replace")


def _notify_tty(message: str) -> None:
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(message)
    except OSError:
        pass


def _user() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
