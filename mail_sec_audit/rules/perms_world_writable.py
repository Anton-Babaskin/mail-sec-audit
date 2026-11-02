"""PERMS.WORLD_WRITABLE: world-writable paths in /etc, /usr/local and /opt"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.scans import WORLD_WRITABLE
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("PERMS.WORLD_WRITABLE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    scan = ctx.facts.scan("world_writable", WORLD_WRITABLE)
    if isinstance(scan, Unavailable):
        return [B.unavailable(scan)]
    risky: list[str] = []
    sticky: list[str] = []
    for entry in scan.entries:
        kind, _, rest = entry.partition(" ")
        mode, _, path = rest.partition(" ")
        target = sticky if kind == "d" and mode.isdigit() and int(mode, 8) & 0o1000 else risky
        target.append(f"{kind} {mode} {path}")
    if risky:
        return [B.warn(count=len(risky), evidence=[ev(scan.source, *risky, limit=50)])]
    if not scan.complete:
        return [B.unknown("permission_denied" if ctx.host.euid else "truncated", source=scan.source)]
    if sticky:
        return [B.info("sticky", count=len(sticky), evidence=[ev(scan.source, *sticky, limit=20)])]
    return [B.ok(evidence=[ev(scan.source)])]
