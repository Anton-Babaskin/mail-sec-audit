"""Mail queue size per MTA."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Union

from ..host import Host
from ..runner import Runner
from ..stacks.base import Stack
from .base import Unavailable, from_result


@dataclass(frozen=True)
class QueueSize:
    count: int
    source: str
    sample: tuple[str, ...] = ()


def collect(host: Host, runner: Runner, stack: Stack) -> Union[QueueSize, Unavailable]:
    if stack.mta == "postfix":
        # JSON lines (Postfix >= 3.1) count long queue IDs correctly.
        result = runner.run(stack.postfix_argv("postqueue", "-j"))
        if result.ok:
            lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
            return QueueSize(len(lines), f"cmd:{result.display}", tuple(lines[:5]))
        legacy = runner.run(stack.postfix_argv("postqueue", "-p"))
        if not legacy.ok:
            return from_result(result if "invalid option" not in result.stderr else legacy)
        if "Mail queue is empty" in legacy.stdout:
            return QueueSize(0, f"cmd:{legacy.display}")
        match = re.search(r"in (\d+) Requests?\.", legacy.stdout)
        if not match:
            return Unavailable("parse_error", f"cmd:{legacy.display}")
        return QueueSize(int(match.group(1)), f"cmd:{legacy.display}")
    if stack.mta == "exim":
        program = "exim4" if runner.which("exim4") else "exim"
        result = runner.run([program, "-bpc"])
        if not result.ok:
            return from_result(result)
        text = result.stdout.strip()
        if not text.isdigit():
            return Unavailable("parse_error", f"cmd:{result.display}")
        return QueueSize(int(text), f"cmd:{result.display}")
    if stack.mta == "sendmail":
        result = runner.run(["mailq"])
        if not result.ok:
            return from_result(result)
        if "is empty" in result.stdout:
            return QueueSize(0, f"cmd:{result.display}")
        match = re.search(r"Total requests: (\d+)", result.stdout)
        if not match:
            return Unavailable("parse_error", f"cmd:{result.display}")
        return QueueSize(int(match.group(1)), f"cmd:{result.display}")
    return Unavailable("not_applicable", f"mta:{stack.mta}", "queue size is checked for Postfix, Exim and Sendmail")
