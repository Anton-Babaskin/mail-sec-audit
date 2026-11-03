"""Shared types for fact collectors."""

from __future__ import annotations

from dataclasses import dataclass

from ..host import FileRead
from ..model import Reason
from ..render.sanitize import clean
from ..runner import CommandResult, ExecState, failure_reason


@dataclass(frozen=True)
class Unavailable:
    """A fact that could not be collected, with the reason for UNKNOWN."""

    reason: str
    source: str
    detail: str = ""
    tool: str = ""


def from_result(result: CommandResult) -> Unavailable:
    reason = failure_reason(result)
    detail = ""
    if result.state is ExecState.NONZERO:
        first = next((line for line in result.stderr.splitlines() if line.strip()), "")
        detail = clean(first or f"exit {result.returncode}", 160)
    return Unavailable(reason, f"cmd:{result.display}", detail, result.argv[0] if result.argv else "")


def from_file(read: FileRead) -> Unavailable:
    reason = {
        "missing": Reason.NO_DATA,
        "denied": Reason.PERMISSION_DENIED,
        "truncated": Reason.TRUNCATED,
    }.get(read.state, Reason.COMMAND_FAILED)
    return Unavailable(reason, f"file:{read.path}", read.detail)
