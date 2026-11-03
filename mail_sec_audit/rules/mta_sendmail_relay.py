"""MTA.SENDMAIL_RELAY: Sendmail relay features"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MTA.SENDMAIL_RELAY")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().mta != "sendmail":
        return [B.na("na")]
    mc = ctx.facts.sendmail()
    if isinstance(mc, Unavailable):
        return [B.unavailable(mc)]
    evidence = [ev(mc.source, *(f"FEATURE({f})" for f in mc.features))]
    if "promiscuous_relay" in mc.features:
        return [B.fail(evidence=evidence)]
    return [B.info(features=", ".join(mc.features) or "-", evidence=evidence)]
