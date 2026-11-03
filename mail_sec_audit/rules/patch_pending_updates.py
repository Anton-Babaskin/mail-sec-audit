"""PATCH.PENDING_UPDATES: pending package updates; security updates are WARN"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("PATCH.PENDING_UPDATES")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    pending = ctx.facts.pending_updates()
    if isinstance(pending, Unavailable):
        return [B.unavailable(pending)]
    if pending.security:
        return [
            B.warn(
                "security",
                count=len(pending.security),
                total=len(pending.packages),
                evidence=[ev(pending.source, *pending.security)],
            )
        ]
    if pending.packages and pending.manager == "dnf":
        return [B.warn("unclassified", count=len(pending.packages), evidence=[ev(pending.source, *pending.packages)])]
    if pending.packages:
        return [B.info("pending", count=len(pending.packages), evidence=[ev(pending.source, *pending.packages)])]
    return [B.ok(manager=pending.manager, evidence=[ev(pending.source)])]
