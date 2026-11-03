"""SUID.FULL_SCAN: --deep: all SUID and executable SGID files"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.scans import FULL_SUID
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SUID.FULL_SCAN", deep=True)
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    scan = ctx.facts.scan("suid_full", FULL_SUID)
    if isinstance(scan, Unavailable):
        return [B.unavailable(scan)]
    if not scan.complete and not scan.entries:
        return [B.unknown("truncated", source=scan.source)]
    return [
        B.info(
            count=len(scan.entries),
            complete=(scan.complete and "yes") or "no",
            evidence=[ev(scan.source, *sorted(scan.entries), limit=200)],
        )
    ]
