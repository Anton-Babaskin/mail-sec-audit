"""PATCH.AUTO_UPDATES: automatic security updates"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("PATCH.AUTO_UPDATES")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    state = ctx.facts.auto_updates()
    if isinstance(state, Unavailable):
        return [B.unavailable(state)]
    evidence = [ev(state.source, *state.lines)]
    if state.enabled:
        return [B.info("enabled", manager=state.manager, evidence=evidence)]
    return [B.info("disabled", manager=state.manager, evidence=evidence)]
