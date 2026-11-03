"""SUID.STANDARD_PATHS: SUID files in system directories (inventory)"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.scans import SUID_STANDARD
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SUID.STANDARD_PATHS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    scan = ctx.facts.scan("suid_standard", SUID_STANDARD)
    if isinstance(scan, Unavailable):
        return [B.unavailable(scan)]
    return [B.info(count=len(scan.entries), evidence=[ev(scan.source, *sorted(scan.entries), limit=60)])]
