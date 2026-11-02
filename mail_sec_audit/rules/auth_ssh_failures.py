"""AUTH.SSH_FAILURES: SSH authentication failures in the period"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from ..facts.maillog import LogResult
from ..model import Finding
from .base import Builder, Check, Ctx, ev

STATE_REASON = {
    "denied": "permission_denied",
    "missing": "missing_tool",
    "timeout": "timeout",
    "truncated": "truncated",
    "error": "command_failed",
}


def _source_problem(result: LogResult) -> Optional[tuple[str, str]]:
    if result.read.in_period == 0 and result.read.failed_sources:
        return result.read.failed_sources[0]
    return None


CHECK = Check("AUTH.SSH_FAILURES")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.runner.which("sshd") is None:
        return [B.na("na")]
    result = ctx.facts.ssh_logs()
    problem = _source_problem(result)
    if problem:
        return [B.unknown(STATE_REASON.get(problem[1], "no_data"), source=problem[0])]
    if result.read.readable_sources == 0:
        return [B.unknown("no_data", source="log:ssh")]
    counter = result.auth
    stats = ctx.extra.setdefault("auth_statistics", {})
    stats["ssh_failed"] = counter.top(counter.ssh_failed_ips)
    stats["ssh_accepted"] = counter.top(counter.ssh_accepted_ips)
    stats["ssh_counts"] = {
        "failed": counter.ssh_failed,
        "invalid_user": counter.ssh_invalid,
        "accepted": counter.ssh_accepted,
    }
    rate = counter.ssh_failed // max(1, ctx.config.days)
    evidence = [
        ev("log:ssh", f"failed={counter.ssh_failed} invalid_user={counter.ssh_invalid} accepted={counter.ssh_accepted}")
    ]
    failed, invalid, accepted = counter.ssh_failed, counter.ssh_invalid, counter.ssh_accepted
    if rate > 100:
        return [B.warn(evidence=evidence, rate=rate, failed=failed, invalid=invalid, accepted=accepted)]
    return [B.info(evidence=evidence, rate=rate, failed=failed, invalid=invalid, accepted=accepted)]
