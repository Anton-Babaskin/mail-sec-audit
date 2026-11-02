"""DISK.USAGE: filesystem space thresholds 85%/95%"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("DISK.USAGE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    usage = ctx.facts.disk_space()
    if isinstance(usage, Unavailable):
        return [B.unavailable(usage)]
    if CHECK.id == "DISK.USAGE":
        ctx.extra["filesystems"] = [
            {
                "filesystem": u.filesystem,
                "bytes_total": u.total,
                "bytes_used": u.used,
                "bytes_available": u.available,
                "used_percent": u.percent,
                "mountpoint": u.mountpoint,
            }
            for u in usage.items
        ]
    findings = []
    for u in usage.items:
        line = f"{u.filesystem} {u.percent}% {u.mountpoint}"
        if u.percent >= 95:
            findings.append(
                B.fail(subject=u.mountpoint, mount=u.mountpoint, percent=u.percent, evidence=[ev(usage.source, line)])
            )
        elif u.percent >= 85:
            findings.append(
                B.warn(subject=u.mountpoint, mount=u.mountpoint, percent=u.percent, evidence=[ev(usage.source, line)])
            )
    if findings:
        return findings
    if not usage.items:
        return [B.unknown("no_data", source=usage.source)]
    return [
        B.ok(
            count=len(usage.items), evidence=[ev(usage.source, *(f"{u.percent}% {u.mountpoint}" for u in usage.items))]
        )
    ]
