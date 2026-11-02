"""SCHED.INVENTORY: cron and systemd timer inventory"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.systemd import Lines
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SCHED.INVENTORY")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    sched = ctx.facts.schedule()
    timers = ctx.facts.timers()
    timer_lines = timers.lines if isinstance(timers, Lines) else ()
    lines = [f"/etc/cron.d/{n}" for n in sched.cron_d]
    lines += [f"crontab {user}: {count} active" for user, count in sched.user_crontabs]
    lines += [f"unit /etc/systemd/system/{n}" for n in sched.custom_units]
    if ctx.config.deep:
        lines += [f"timer {t}" for t in timer_lines]
    finding = B.info(
        cron_d=len(sched.cron_d),
        crontabs=len(sched.user_crontabs),
        timers=len(timer_lines),
        units=len(sched.custom_units),
        evidence=[ev("file:/etc/cron.d", *lines, limit=80)],
    )
    if not sched.crontabs_readable:
        return [finding, B.unknown("permission_denied", source="file:/var/spool/cron")]
    return [finding]
