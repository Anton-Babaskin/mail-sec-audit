"""SUID.UNEXPECTED_LOCATIONS: SUID files in home and temporary directories"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.scans import SUID_USER_DIRS
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SUID.UNEXPECTED_LOCATIONS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    scan = ctx.facts.scan("suid_user", SUID_USER_DIRS)
    if isinstance(scan, Unavailable):
        return [B.unavailable(scan)]
    if scan.entries:
        return [B.fail(count=len(scan.entries), evidence=[ev(scan.source, *scan.entries, limit=30)])]
    if not scan.complete:
        return [B.unknown("permission_denied" if ctx.host.euid else "truncated", source=scan.source)]
    return [B.ok(evidence=[ev(scan.source)])]
