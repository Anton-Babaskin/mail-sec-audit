"""USERS.INTERACTIVE_ACCOUNTS: accounts with a login shell"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("USERS.INTERACTIVE_ACCOUNTS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    accounts = ctx.facts.accounts()
    if isinstance(accounts, Unavailable):
        return [B.unavailable(accounts)]
    users = [a for a in accounts.items if a.interactive]
    lines = [f"{a.name} uid={a.uid} home={a.home} shell={a.shell}" for a in users]
    return [B.info(count=len(users), evidence=[ev(accounts.source, *lines, limit=40)])]
