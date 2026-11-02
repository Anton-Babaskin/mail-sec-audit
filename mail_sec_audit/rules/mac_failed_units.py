"""MAC.FAILED_UNITS: failed systemd units"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("MAC.FAILED_UNITS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    failed = ctx.facts.failed_units()
    if isinstance(failed, Unavailable):
        if failed.reason == Reason.NOT_APPLICABLE:
            return [B.na("na")]
        return [B.unavailable(failed)]
    if failed.lines:
        return [B.warn(count=len(failed.lines), evidence=[ev(failed.source, *failed.lines, limit=20)])]
    return [B.ok(evidence=[ev(failed.source)])]
