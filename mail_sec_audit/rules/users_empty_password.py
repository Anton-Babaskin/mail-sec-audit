"""USERS.EMPTY_PASSWORD: accounts without a password"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("USERS.EMPTY_PASSWORD")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    status = ctx.facts.password_status()
    if isinstance(status, Unavailable):
        return [B.unavailable(status)]
    if status.empty:
        return [B.fail(names=", ".join(status.empty), evidence=[ev(status.source, *(f"{n} NP" for n in status.empty))])]
    return [B.ok(evidence=[ev(status.source)])]
