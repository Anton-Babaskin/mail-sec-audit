"""AUTH.MAIL_FAILURES: mail authentication failures in the period"""

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


CHECK = Check("AUTH.MAIL_FAILURES")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    if stack.mta == "none" and stack.imap == "none":
        return [B.na("na")]
    result = ctx.facts.mail_logs()
    problem = _source_problem(result)
    if problem:
        return [B.unknown(STATE_REASON.get(problem[1], "no_data"), source=problem[0])]
    if result.read.readable_sources == 0:
        return [B.unknown("no_data", source="log:mail")]
    counter = result.auth
    ctx.extra.setdefault("auth_statistics", {})["mail_failed"] = counter.top(counter.mail_failed_ips)
    rate = counter.mail_failed // max(1, ctx.config.days)
    evidence = [ev("log:mail", f"failed={counter.mail_failed}")]
    if rate > 300:
        return [B.warn(failed=counter.mail_failed, rate=rate, evidence=evidence)]
    return [B.info(failed=counter.mail_failed, rate=rate, evidence=evidence)]
