"""Out-of-band approval: the human decides, not the model.

Every backend fails closed. If no human can be reached before the timeout,
the action is denied.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import select
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .redact import redact


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
            with open(device, "r+"):
                return True
        except OSError:
            return False

    def request(self, verdict) -> ApprovalResult:
        try:
            tty = open(self.device, "r+")
        except OSError:
            return ApprovalResult(False, "tty", "no terminal available; denied")
        with tty:
            tty.write("\n" + _banner(verdict) + "\n")
            tty.write(f"Type 'yes' to allow this once (auto-deny in {self.timeout}s): ")
            tty.flush()
            ready, _, _ = select.select([tty], [], [], self.timeout)
            if not ready:
                tty.write("\nNo answer. Denied.\n")
                return ApprovalResult(False, "tty", "timed out")
            answer = tty.readline().strip().lower()
        if answer == "yes":
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


def _banner(verdict) -> str:
    action = verdict.action
    text = redact(action.display())
    if len(text) > 600:
        text = text[:600] + " ..."
    return (
        "=" * 64
        + "\n BRAKEPOINT: an agent wants to run an action that needs your approval\n"
        + "=" * 64
        + f"\n Action ({action.kind}, via {action.origin}):\n   {text}\n\n"
        + "\n".join(" " + line for line in verdict.reason(audience="human").splitlines())
        + "\n"
        + "=" * 64
    )


def _notify_tty(message: str) -> None:
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(message)
    except OSError:
        pass


def _user() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
