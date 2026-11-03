"""USERS.UID0: only root has UID 0"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("USERS.UID0")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    accounts = ctx.facts.accounts()
    if isinstance(accounts, Unavailable):
        return [B.unavailable(accounts)]
    names = [a.name for a in accounts.items if a.uid == 0]
    evidence = [ev(accounts.source, *(f"{n}:0" for n in names))]
    if len(names) > 1:
        return [B.fail(names=", ".join(names), evidence=evidence)]
    return [B.ok(evidence=evidence)]
