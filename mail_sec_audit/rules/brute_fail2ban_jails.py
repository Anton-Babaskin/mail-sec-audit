"""BRUTE.FAIL2BAN_JAILS: Fail2ban jails and counters"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.fail2ban import NotInstalled
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("BRUTE.FAIL2BAN_JAILS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    state = ctx.facts.fail2ban()
    if isinstance(state, NotInstalled):
        return [B.na("na")]
    if isinstance(state, Unavailable):
        return [B.unavailable(state)]
    if not state.responding:
        return [B.na("not_running")]
    if not state.jails:
        return [B.warn(evidence=[ev(state.source, "Jail list: (empty)")])]
    lines = [
        f"{j.name}: banned={j.banned if j.banned is not None else '?'} total={j.total if j.total is not None else '?'}"
        for j in state.jails
    ]
    banned = sum(j.banned or 0 for j in state.jails)
    return [B.info(count=len(state.jails), banned=banned, evidence=[ev(state.source, *lines, limit=30)])]
