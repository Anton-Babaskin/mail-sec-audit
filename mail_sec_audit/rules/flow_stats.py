"""FLOW.STATS: Postfix traffic statistics for the period"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

STATE_REASON = {
    "denied": "permission_denied",
    "missing": "no_data",
    "timeout": "timeout",
    "truncated": "truncated",
    "error": "command_failed",
    "empty": "no_data",
}


CHECK = Check("FLOW.STATS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    if stack.mta != "postfix":
        return [B.na("na", mta=stack.mta)]
    result = ctx.facts.mail_logs()
    read = result.read
    if not read.in_period or result.statistics is None:
        if read.failed_sources:
            source, state = read.failed_sources[0]
            return [B.unknown(STATE_REASON.get(state, "no_data"), source=source)]
        return [B.unknown("no_data", source="log:mail")]
    stats = result.statistics
    ctx.extra["mail_statistics"] = stats
    totals = stats["totals"]
    if totals["tracked_queue_ids"] == 0:
        return [B.unknown("parse_error", source="log:mail")]
    evidence = [
        ev(
            "log:mail",
            f"lines in period {read.in_period} of {read.scanned}",
            f"unparsed postfix lines {stats.get('unparsed_postfix_lines', 0)}",
        )
    ]
    return [
        B.info(
            messages=totals["outbound_messages"],
            deliveries=totals["outbound_deliveries"],
            incoming=totals["incoming_messages"],
            evidence=evidence,
        )
    ]
