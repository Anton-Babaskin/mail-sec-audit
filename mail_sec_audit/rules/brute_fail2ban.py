"""BRUTE.FAIL2BAN: Fail2ban answers"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.fail2ban import NotInstalled
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("BRUTE.FAIL2BAN")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    state = ctx.facts.fail2ban()
    if isinstance(state, NotInstalled):
        return [B.na("na")]
    if isinstance(state, Unavailable):
        return [B.unavailable(state)]
    if state.responding:
        return [B.ok(evidence=[ev(state.source, "pong")])]
    return [B.fail(evidence=[ev(state.source, "no pong")])]
